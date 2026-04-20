"""Install-time behavior heuristics."""

from __future__ import annotations

import json
import re

from packguard.models import ExtractionResult, Finding, ResolvedPackage


INSTALL_SCRIPT_NAMES = {"preinstall", "install", "postinstall", "prepare", "prepack"}
NETWORK_LAUNCH_PATTERN = re.compile(
    r"(curl|wget|Invoke-WebRequest|powershell|bash\s+-c|node\s+-e|python\s+-c)"
)
SECRET_ACCESS_PATTERN = re.compile(r"(process\.env|os\.environ|AWS_|GITHUB_|NPM_|PYPI_|KUBECONFIG)")
STARTUP_FILE_PATTERN = re.compile(r"\.pth$")
ENTRYPOINT_PATTERN = re.compile(r"(sitecustomize|usercustomize|pytest11)")
BUILD_HOOK_PATTERN = re.compile(r"(build-system|build-backend|setup_requires|entry_points)")


class BehaviorScanner:
    def scan(self, package: ResolvedPackage, extraction: ExtractionResult) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_npm_manifests(extraction))
        findings.extend(self._scan_python_install_paths(extraction))
        return findings

    def _scan_npm_manifests(self, extraction: ExtractionResult) -> list[Finding]:
        findings: list[Finding] = []
        for manifest in extraction.metadata_files:
            if manifest.name != "package.json":
                continue
            try:
                payload = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue

            scripts = payload.get("scripts", {})
            for script_name, command in scripts.items():
                if script_name not in INSTALL_SCRIPT_NAMES:
                    continue
                location = str(manifest.relative_to(extraction.root_dir))
                severity = "medium"
                confidence = "medium"
                summary = "Runs automatically during install or packaging."
                rationale = "Install-time hooks execute before the user has inspected the installed code."
                tags = ["install-time", "npm"]
                if NETWORK_LAUNCH_PATTERN.search(command):
                    severity = "high"
                    confidence = "high"
                    summary = "Install script launches a shell or remote fetch path."
                    rationale = "Network-capable install hooks are frequently used as staged loaders."
                    tags.append("loader")
                findings.append(
                    Finding(
                        rule_id="behavior.install-script",
                        title="Install-time script",
                        summary=summary,
                        severity=severity,
                        confidence=confidence,
                        family="behavior",
                        phase="install",
                        rationale=rationale,
                        detector="behavior",
                        location=location,
                        evidence=[f"{script_name}: {command}"],
                        tags=tags,
                    )
                )
        return findings

    def _scan_python_install_paths(self, extraction: ExtractionResult) -> list[Finding]:
        findings: list[Finding] = []
        for metadata_file in extraction.metadata_files:
            relative_path = str(metadata_file.relative_to(extraction.root_dir))
            if STARTUP_FILE_PATTERN.search(metadata_file.name):
                findings.append(
                    Finding(
                        rule_id="behavior.python-startup-hook",
                        title="Python startup hook",
                        summary="A .pth file executes on interpreter startup and is a common persistence vector.",
                        severity="high",
                        confidence="high",
                        family="behavior",
                        phase="startup",
                        rationale="Startup hooks run automatically and can persist far beyond package installation.",
                        detector="behavior",
                        location=relative_path,
                        evidence=["Detected .pth startup file"],
                        tags=["python", "startup", "persistence"],
                    )
                )
                continue

            if metadata_file.name not in {"setup.py", "pyproject.toml", "setup.cfg"}:
                continue

            try:
                content = metadata_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            if BUILD_HOOK_PATTERN.search(content):
                findings.append(
                    Finding(
                        rule_id="behavior.python-build-hook",
                        title="Python build/install hook",
                        summary="Package defines Python build or installer metadata that can execute during build time.",
                        severity="medium",
                        confidence="medium",
                        family="behavior",
                        phase="build",
                        rationale="Build backends and setup hooks execute before package code is imported by the application.",
                        detector="behavior",
                        location=relative_path,
                        evidence=["Python packaging hook markers detected"],
                        tags=["python", "build", "install-time"],
                    )
                )

            if SECRET_ACCESS_PATTERN.search(content):
                findings.append(
                    Finding(
                        rule_id="behavior.env-sensitive-install",
                        title="Environment-aware install logic",
                        summary="Install-time code reads environment variables and may behave differently on developer or CI machines.",
                        severity="high",
                        confidence="medium",
                        family="behavior",
                        phase="install",
                        rationale="Environment-gated install logic is a common tactic for evading sandboxes and targeting CI secrets.",
                        detector="behavior",
                        location=relative_path,
                        evidence=["Sensitive environment variable references found"],
                        tags=["python", "install-time", "evasion"],
                    )
                )

            if ENTRYPOINT_PATTERN.search(content):
                findings.append(
                    Finding(
                        rule_id="behavior.suspicious-entrypoint",
                        title="Suspicious Python entry point",
                        summary="Package references Python entry points commonly used to extend or hijack execution contexts.",
                        severity="medium",
                        confidence="medium",
                        family="behavior",
                        phase="startup",
                        rationale="Hooking entry points expands code execution into developer or test workflows.",
                        detector="behavior",
                        location=relative_path,
                        evidence=["Entry point markers matched sitecustomize/usercustomize/pytest11"],
                        tags=["python", "entrypoint", "persistence"],
                    )
                )

        return findings
