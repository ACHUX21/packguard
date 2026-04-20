"""Configuration loading and defaults."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from packguard.errors import ConfigError

try:
    import yaml
except ImportError:
    yaml = None


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _package_root() -> Path:
    return Path(__file__).resolve().parent


def _default_repo_or_package_path(repo_relative: str, package_relative: str) -> Path:
    repo_candidate = (_repo_root() / repo_relative).resolve()
    if repo_candidate.exists():
        return repo_candidate
    return (_package_root() / package_relative).resolve()


@dataclass(slots=True)
class Config:
    log_level: str = "INFO"
    output_path: str = "reports/packguard-report.json"
    offline_mode: bool = False
    max_file_bytes: int = 300_000
    scanners: list[str] = field(
        default_factory=lambda: ["threat_feed", "typosquat", "behavior", "static"]
    )
    fail_on: str = "malicious"
    risk_thresholds: dict[str, int] = field(
        default_factory=lambda: {"clean": 0, "suspicious": 35, "malicious": 75}
    )
    typosquat_distance: int = 1
    trusted_scopes: list[str] = field(default_factory=lambda: ["@types", "@angular", "@aws-sdk"])
    private_namespaces: list[str] = field(default_factory=list)
    popular_packages_path: str = str(
        _default_repo_or_package_path(
            "data/intel/popular_packages.txt",
            "resources/intel/popular_packages.txt",
        )
    )
    malicious_feed_path: str = str(
        _default_repo_or_package_path(
            "data/intel/malicious_packages.json",
            "resources/intel/malicious_packages.json",
        )
    )
    use_ai: bool = False
    ai_provider: str = "ollama"
    ai_timeout_seconds: int = 20
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    openai_base_url: str = "https://api.openai.com/v1"
    openai_api_key: str = ""
    openai_model: str = "gpt-5-mini"
    anthropic_base_url: str = "https://api.anthropic.com/v1"
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-20250514"
    gemini_base_url: str = "https://generativelanguage.googleapis.com/v1beta"
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    groq_base_url: str = "https://api.groq.com/openai/v1"
    groq_api_key: str = ""
    groq_model: str = "openai/gpt-oss-20b"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_api_key: str = ""
    openrouter_model: str = "openai/gpt-5-mini"
    xai_base_url: str = "https://api.x.ai/v1"
    xai_api_key: str = ""
    xai_model: str = "grok-4.20-reasoning"


def load_config(config_path: str | None = None) -> Config:
    config = Config(
        log_level=os.getenv("PACKGUARD_LOG_LEVEL", "INFO"),
        use_ai=os.getenv("PACKGUARD_USE_AI", "false").lower() == "true",
        ai_provider=os.getenv("PACKGUARD_AI_PROVIDER", "ollama"),
        ai_timeout_seconds=int(os.getenv("PACKGUARD_AI_TIMEOUT_SECONDS", "20")),
        ollama_host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        ollama_model=os.getenv("OLLAMA_MODEL", "llama3.2"),
        openai_base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        openai_api_key=os.getenv("OPENAI_API_KEY", ""),
        openai_model=os.getenv("OPENAI_MODEL", "gpt-5-mini"),
        anthropic_base_url=os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1"),
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
        anthropic_model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
        gemini_base_url=os.getenv("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"),
        gemini_api_key=os.getenv("GEMINI_API_KEY", ""),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
        groq_base_url=os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1"),
        groq_api_key=os.getenv("GROQ_API_KEY", ""),
        groq_model=os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"),
        openrouter_base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        openrouter_api_key=os.getenv("OPENROUTER_API_KEY", ""),
        openrouter_model=os.getenv("OPENROUTER_MODEL", "openai/gpt-5-mini"),
        xai_base_url=os.getenv("XAI_BASE_URL", "https://api.x.ai/v1"),
        xai_api_key=os.getenv("XAI_API_KEY", ""),
        xai_model=os.getenv("XAI_MODEL", "grok-4.20-reasoning"),
    )

    if config_path is None:
        _resolve_path_fields(config, Path.cwd())
        return config

    path = Path(config_path).resolve()
    if not path.exists():
        raise ConfigError(f"Config file '{path}' does not exist")

    overrides = _read_config_file(path)
    valid_fields = {field.name for field in fields(Config)}
    sanitized = {key: value for key, value in overrides.items() if key in valid_fields}
    for key, value in sanitized.items():
        setattr(config, key, value)
    _resolve_path_fields(config, path.parent)
    return config


def _read_config_file(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Could not read config file '{path}': {exc}") from exc

    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            return json.loads(raw)
        if suffix in {".yaml", ".yml"}:
            if yaml is None:
                raise ConfigError("PyYAML is required to load YAML config files")
            return yaml.safe_load(raw) or {}
    except Exception as exc:
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError(f"Could not parse config file '{path}': {exc}") from exc

    raise ConfigError(f"Unsupported config format for '{path}'")


def _resolve_path_fields(config: Config, base_dir: Path) -> None:
    for field_name in ("popular_packages_path", "malicious_feed_path"):
        value = getattr(config, field_name)
        path = Path(value)
        if not path.is_absolute():
            base_candidate = (base_dir / path).resolve()
            root_candidate = (_repo_root() / path).resolve()
            if base_candidate.exists() or not root_candidate.exists():
                setattr(config, field_name, str(base_candidate))
            else:
                setattr(config, field_name, str(root_candidate))

    output_path = Path(config.output_path)
    if not output_path.is_absolute():
        config.output_path = str((base_dir / output_path).resolve())
