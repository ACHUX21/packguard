"""Shared AI explainability primitives."""

from __future__ import annotations

import json
from typing import Any
from urllib import error, request

from packguard.config import Config
from packguard.models import Finding, ResolvedPackage


class BaseExplainer:
    provider_name = "unknown"

    def __init__(self, config: Config):
        self.config = config

    def available(self) -> bool:
        return self.status() == "ready"

    def status(self) -> str:
        if not self.config.use_ai:
            return "disabled"
        return "ready"

    def selected_model(self) -> str | None:
        return None

    def metadata(self) -> dict[str, Any]:
        return {
            "enabled": self.config.use_ai,
            "provider": self.provider_name,
            "model": self.selected_model(),
            "status": self.status(),
        }

    def summarize(self, package: ResolvedPackage, findings: list[Finding]) -> tuple[str | None, str]:
        if not self.config.use_ai:
            return None, "disabled"
        if self.status() != "ready":
            return None, self.status()
        if not findings:
            return None, "skipped-no-findings"

        try:
            summary = self._generate_summary(package, findings)
        except Exception as exc:  # pragma: no cover - defensive boundary
            return None, f"error:{exc.__class__.__name__}"
        return summary, "generated" if summary else "empty"

    def _generate_summary(self, package: ResolvedPackage, findings: list[Finding]) -> str | None:
        raise NotImplementedError

    def _build_prompt(self, package: ResolvedPackage, findings: list[Finding]) -> str:
        rendered_findings = "\n".join(
            (
                f"- [{finding.severity}/{finding.confidence}] "
                f"{finding.title}: {finding.summary} @ {finding.location}"
            )
            for finding in findings[:12]
        )
        return (
            "You are summarizing security findings for a local package malware scan.\n"
            "Do not change the verdict. Explain the most important signals, likely attack path, "
            "and what a developer should review first in under 120 words.\n\n"
            f"Package: {package.coordinate.source}:{package.coordinate.name}@"
            f"{package.coordinate.version}\n"
            f"Findings:\n{rendered_findings}\n"
        )


class HttpExplainer(BaseExplainer):
    def _post_json(
        self,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        request_headers = {"Content-Type": "application/json", **headers}
        req = request.Request(url=url, data=body, headers=request_headers, method="POST")
        try:
            with request.urlopen(req, timeout=self.config.ai_timeout_seconds) as response:
                raw = response.read().decode("utf-8")
        except error.HTTPError as exc:
            raise RuntimeError(f"http-{exc.code}") from exc
        except error.URLError as exc:
            raise RuntimeError("network-error") from exc
        return json.loads(raw) if raw else {}
