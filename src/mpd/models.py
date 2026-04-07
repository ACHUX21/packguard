"""Data models."""
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class Package:
    name: str
    version: str
    source: str  # "npm" or "pypi"
    url: str

@dataclass
class AnalysisResult:
    package: Package
    suspicious: bool = False
    reasons: List[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.reasons is None:
            self.reasons = []
        if self.metadata is None:
            self.metadata = {}
