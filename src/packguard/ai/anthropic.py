"""Anthropic-backed explainability."""

from __future__ import annotations

from typing import Any

from packguard.ai.base import HttpExplainer
from packguard.models import Finding, ResolvedPackage


class AnthropicExplainer(HttpExplainer):
    provider_name = "anthropic"

    def status(self) -> str:
        if not self.config.use_ai:
            return "disabled"
        if not self.config.anthropic_api_key:
            return "missing-api-key"
        return "ready"

    def selected_model(self) -> str | None:
        return self.config.anthropic_model

    def _generate_summary(self, package: ResolvedPackage, findings: list[Finding]) -> str | None:
        response = self._post_json(
            f"{self.config.anthropic_base_url.rstrip('/')}/messages",
            headers={
                "x-api-key": self.config.anthropic_api_key,
                "anthropic-version": "2023-06-01",
            },
            payload={
                "model": self.config.anthropic_model,
                "max_tokens": 180,
                "system": (
                    "You are a security explainer for package malware findings. "
                    "Do not change verdicts. Keep the answer under 120 words."
                ),
                "messages": [{"role": "user", "content": self._build_prompt(package, findings)}],
            },
        )
        return self._extract_text(response)

    def _extract_text(self, response: dict[str, Any]) -> str | None:
        for block in response.get("content", []):
            if block.get("type") == "text":
                text = block.get("text")
                if isinstance(text, str) and text.strip():
                    return text.strip()
        return None
