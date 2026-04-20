"""Google Gemini-backed explainability."""

from __future__ import annotations

from typing import Any

from packguard.ai.base import HttpExplainer
from packguard.models import Finding, ResolvedPackage


class GeminiExplainer(HttpExplainer):
    provider_name = "gemini"

    def status(self) -> str:
        if not self.config.use_ai:
            return "disabled"
        if not self.config.gemini_api_key:
            return "missing-api-key"
        return "ready"

    def selected_model(self) -> str | None:
        return self.config.gemini_model

    def _generate_summary(self, package: ResolvedPackage, findings: list[Finding]) -> str | None:
        response = self._post_json(
            f"{self.config.gemini_base_url.rstrip('/')}/models/"
            f"{self.config.gemini_model}:generateContent",
            headers={"x-goog-api-key": self.config.gemini_api_key},
            payload={
                "systemInstruction": {
                    "parts": [
                        {
                            "text": (
                                "You are a security explainer for package malware findings. "
                                "Do not change verdicts. Keep the answer under 120 words."
                            )
                        }
                    ]
                },
                "contents": [{"parts": [{"text": self._build_prompt(package, findings)}]}],
            },
        )
        return self._extract_text(response)

    def _extract_text(self, response: dict[str, Any]) -> str | None:
        for candidate in response.get("candidates", []):
            content = candidate.get("content", {})
            for part in content.get("parts", []):
                text = part.get("text")
                if isinstance(text, str) and text.strip():
                    return text.strip()
        return None
