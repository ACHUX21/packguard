from .npm_extractor import NpmExtractor
from .pypi_extractor import PyPIExtractor

_extractors = {
    "npm": NpmExtractor(),
    "pypi": PyPIExtractor()
}

def get_extractor(source: str):
    if source not in _extractors:
        raise ValueError(f"Unknown source: {source}")
    return _extractors[source]
