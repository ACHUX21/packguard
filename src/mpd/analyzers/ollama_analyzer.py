import ollama
from mpd.analyzers.base import Analyzer
from mpd.config import Config

class OllamaAnalyzer(Analyzer):
    def __init__(self, config: Config):
        self.config = config

    def analyze(self, file_path: str, issues: list) -> dict:
        prompt = f"Analyze these suspicious patterns in {file_path}: {issues}"
        response = ollama.chat(
            model=self.config.ollama_model,
            messages=[{"role": "user", "content": prompt}]
        )
        return {"file": file_path, "analysis": response.message.content, "issues": issues}
