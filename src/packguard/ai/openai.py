"""OpenAI-backed explainability."""

from __future__ import annotations

from typing import Any

from packguard.ai.base import HttpExplainer
from packguard.models import Finding, ResolvedPackage


class OpenAIExplainer(HttpExplainer):
    provider_name = "openai"

    def status(self) -> str:
        if not self.config.use_ai:
            return "disabled"
        if not self.config.openai_api_key:
            return "missing-api-key"
        return "ready"

    def selected_model(self) -> str | None:
        return self.config.openai_model

    def _generate_summary(self, package: ResolvedPackage, findings: list[Finding]) -> str | None:
        response = self._post_json(
            f"{self.config.openai_base_url.rstrip('/')}/responses",
            headers={"Authorization": f"Bearer {self.config.openai_api_key}"},
            payload={
                "model": self.config.openai_model,
                "instructions": (
                    "You are a security explainer for package malware findings. "
                    "Do not change verdicts. Keep the answer under 120 words."
                ),
                "input": self._build_prompt(package, findings),
                "max_output_tokens": 180,
            },
        )
        return self._extract_text(response)

    def _extract_text(self, response: dict[str, Any]) -> str | None:
        output_text = response.get("output_text")
        if isinstance(output_text, str) and output_text.strip():
            return output_text.strip()

        output = response.get("output", [])
        for item in output:
            for content in item.get("content", []):
                if content.get("type") in {"output_text", "text"}:
                    text = content.get("text")
                    if isinstance(text, str) and text.strip():
                        return text.strip()
        return None
