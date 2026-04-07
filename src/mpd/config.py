"""Configuration handling."""
import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

@dataclass
class Config:
    ollama_host: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "llama3.2")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    popular_packages_path: str = "data/popular_packages.txt"

def load(config_path: str | None = None) -> Config:
    return Config()
