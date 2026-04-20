"""Optional Ollama-powered explainability."""

from __future__ import annotations

try:
    import ollama as ollama_module
except ImportError:
    ollama_module = None

from packguard.ai.base import BaseExplainer
from packguard.config import Config
from packguard.models import Finding, ResolvedPackage


class OllamaExplainer(BaseExplainer):
    provider_name = "ollama"

    def __init__(self, config: Config):
        super().__init__(config)
        self.config = config
        self.ollama = ollama_module
        client_class = getattr(self.ollama, "Client", None) if self.ollama else None
        self.client = client_class(host=config.ollama_host) if client_class else None

    def available(self) -> bool:
        return bool(self.config.use_ai and self.ollama is not None)

    def status(self) -> str:
        if not self.config.use_ai:
            return "disabled"
        if self.ollama is None:
            return "unavailable"
        return "ready"

    def selected_model(self) -> str | None:
        return self.config.ollama_model

    def _generate_summary(self, package: ResolvedPackage, findings: list[Finding]) -> str | None:
        prompt = self._build_prompt(package, findings)
        try:
            if self.client is not None:
                response = self.client.chat(
                    model=self.config.ollama_model,
                    messages=[{"role": "user", "content": prompt}],
                )
            else:
                response = self.ollama.chat(
                    model=self.config.ollama_model,
                    messages=[{"role": "user", "content": prompt}],
                )
        except Exception as exc:
            return None, f"error:{exc.__class__.__name__}"

        summary = None
        if isinstance(response, dict):
            summary = response.get("message", {}).get("content")
        else:
            message = getattr(response, "message", None)
            if isinstance(message, dict):
                summary = message.get("content")
            else:
                summary = getattr(message, "content", None)
        return summary
