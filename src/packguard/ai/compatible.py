"""OpenAI-compatible provider integrations."""

from __future__ import annotations

from typing import Any

from packguard.ai.base import HttpExplainer
from packguard.models import Finding, ResolvedPackage


class OpenAICompatibleExplainer(HttpExplainer):
    api_key_field = ""
    base_url_field = ""
    model_field = ""
    provider_name = "compatible"

    def status(self) -> str:
        if not self.config.use_ai:
            return "disabled"
        if not getattr(self.config, self.api_key_field):
            return "missing-api-key"
        return "ready"

    def selected_model(self) -> str | None:
        return getattr(self.config, self.model_field)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {getattr(self.config, self.api_key_field)}"}

    def _generate_summary(self, package: ResolvedPackage, findings: list[Finding]) -> str | None:
        response = self._post_json(
            f"{getattr(self.config, self.base_url_field).rstrip('/')}/chat/completions",
            headers=self._headers(),
            payload={
                "model": getattr(self.config, self.model_field),
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a security explainer for package malware findings. "
                            "Do not change verdicts. Keep the answer under 120 words."
                        ),
                    },
                    {"role": "user", "content": self._build_prompt(package, findings)},
                ],
            },
        )
        return self._extract_text(response)

    def _extract_text(self, response: dict[str, Any]) -> str | None:
        for choice in response.get("choices", []):
            message = choice.get("message", {})
            content = message.get("content")
            if isinstance(content, str) and content.strip():
                return content.strip()
            if isinstance(content, list):
                for block in content:
                    if block.get("type") in {"output_text", "text"}:
                        text = block.get("text")
                        if isinstance(text, str) and text.strip():
                            return text.strip()
        return None


class GroqExplainer(OpenAICompatibleExplainer):
    provider_name = "groq"
    api_key_field = "groq_api_key"
    base_url_field = "groq_base_url"
    model_field = "groq_model"


class OpenRouterExplainer(OpenAICompatibleExplainer):
    provider_name = "openrouter"
    api_key_field = "openrouter_api_key"
    base_url_field = "openrouter_base_url"
    model_field = "openrouter_model"


class XAIExplainer(OpenAICompatibleExplainer):
    provider_name = "xai"
    api_key_field = "xai_api_key"
    base_url_field = "xai_base_url"
    model_field = "xai_model"
