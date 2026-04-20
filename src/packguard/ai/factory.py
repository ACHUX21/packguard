"""AI provider selection."""

from __future__ import annotations

from packguard.ai.anthropic import AnthropicExplainer
from packguard.ai.base import BaseExplainer
from packguard.ai.compatible import GroqExplainer, OpenRouterExplainer, XAIExplainer
from packguard.ai.gemini import GeminiExplainer
from packguard.ai.ollama import OllamaExplainer
from packguard.ai.openai import OpenAIExplainer
from packguard.config import Config


def create_explainer(config: Config) -> BaseExplainer:
    providers = {
        "anthropic": AnthropicExplainer,
        "gemini": GeminiExplainer,
        "groq": GroqExplainer,
        "ollama": OllamaExplainer,
        "openai": OpenAIExplainer,
        "openrouter": OpenRouterExplainer,
        "xai": XAIExplainer,
    }
    provider = config.ai_provider.lower().strip()
    explainer_class = providers.get(provider)
    if explainer_class is None:
        return UnsupportedExplainer(config)
    return explainer_class(config)


class UnsupportedExplainer(BaseExplainer):
    provider_name = "unsupported"

    def status(self) -> str:
        if not self.config.use_ai:
            return "disabled"
        return f"unsupported-provider:{self.config.ai_provider}"

    def selected_model(self) -> str | None:
        return None

    def _generate_summary(self, package, findings):  # pragma: no cover - unreachable via status
        return None
