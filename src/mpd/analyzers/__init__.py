from .ollama_analyzer import OllamaAnalyzer
from mpd.config import load

_analyzer = None

def get_analyzer():
    global _analyzer
    if _analyzer is None:
        config = load()
        _analyzer = OllamaAnalyzer(config)
    return _analyzer
