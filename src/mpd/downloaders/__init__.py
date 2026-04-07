from .npm import NpmDownloader
from .pypi import PyPIDownloader

_downloaders = {
    "npm": NpmDownloader(),
    "pypi": PyPIDownloader()
}

def get_downloader(source: str):
    if source not in _downloaders:
        raise ValueError(f"Unknown source: {source}")
    return _downloaders[source]
