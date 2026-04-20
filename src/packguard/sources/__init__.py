"""Package source registry."""

from packguard.sources.base import PackageSource
from packguard.sources.npm import NpmSource
from packguard.sources.pypi import PyPISource


_SOURCES: dict[str, PackageSource] = {
    "npm": NpmSource(),
    "pypi": PyPISource(),
}


def get_source(source_name: str) -> PackageSource:
    try:
        return _SOURCES[source_name]
    except KeyError as exc:
        raise ValueError(f"Unsupported package source: {source_name}") from exc
