import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from packguard.config import load_config


class ConfigTestCase(unittest.TestCase):
    def test_load_uses_repo_defaults_without_custom_file(self):
        config = load_config(None)

        self.assertEqual(config.ai_provider, "ollama")
        self.assertEqual(config.ai_timeout_seconds, 20)
        self.assertEqual(config.ollama_host, "http://localhost:11434")
        self.assertEqual(config.ollama_model, "llama3.2")
        self.assertEqual(config.openai_model, "gpt-5-mini")
        self.assertEqual(config.anthropic_model, "claude-sonnet-4-20250514")
        self.assertEqual(config.gemini_model, "gemini-2.5-flash")
        self.assertEqual(config.log_level, "INFO")
        self.assertTrue(config.popular_packages_path.endswith("data/intel/popular_packages.txt"))
        self.assertTrue(config.malicious_feed_path.endswith("data/intel/malicious_packages.json"))

    def test_load_applies_json_overrides_and_resolves_relative_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "config.json")
            intel_dir = os.path.join(tmpdir, "intel")
            os.makedirs(intel_dir, exist_ok=True)
            with open(config_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "ai_provider": "openai",
                        "openai_model": "gpt-5",
                        "ollama_model": "llama3.1:8b",
                        "log_level": "DEBUG",
                        "popular_packages_path": "intel/popular.txt",
                        "malicious_feed_path": "intel/malicious.json",
                    },
                    handle,
                )

            config = load_config(config_path)

        self.assertEqual(config.ai_provider, "openai")
        self.assertEqual(config.openai_model, "gpt-5")
        self.assertEqual(config.ollama_model, "llama3.1:8b")
        self.assertEqual(config.log_level, "DEBUG")
        self.assertEqual(config.popular_packages_path, os.path.join(tmpdir, "intel", "popular.txt"))
        self.assertEqual(config.malicious_feed_path, os.path.join(tmpdir, "intel", "malicious.json"))


if __name__ == "__main__":
    unittest.main()
