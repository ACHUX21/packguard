"""PyPI source resolution."""

from __future__ import annotations

import json
import os
from urllib import parse, request

from packguard.errors import SourceError
from packguard.models import PackageCoordinate, ResolvedPackage
from packguard.sources.base import PackageSource


class PyPISource(PackageSource):
    def resolve(self, coordinate: PackageCoordinate) -> ResolvedPackage:
        quoted_name = parse.quote(coordinate.name)
        metadata_url = (
            f"https://pypi.org/pypi/{quoted_name}/{coordinate.version}/json"
            if coordinate.version
            else f"https://pypi.org/pypi/{quoted_name}/json"
        )

        try:
            with request.urlopen(metadata_url, timeout=30) as response:
                payload = json.load(response)
        except Exception as exc:
            raise SourceError(
                f"Failed to fetch PyPI metadata for '{coordinate.name}': {exc}"
            ) from exc

        version = coordinate.version or payload.get("info", {}).get("version")
        if not version:
            raise SourceError(f"Could not determine version for PyPI package '{coordinate.name}'")

        artifact = self._pick_artifact(payload, version)
        if not artifact:
            raise SourceError(
                f"Could not determine downloadable artifact for PyPI package '{coordinate.name}'"
            )

        coordinate.version = version
        artifact_url = artifact["url"]
        digests = artifact.get("digests", {})
        hash_value = digests.get("sha256") or digests.get("md5")
        return ResolvedPackage(
            coordinate=coordinate,
            metadata_url=metadata_url,
            artifact_url=artifact_url,
            artifact_filename=artifact.get("filename")
            or os.path.basename(parse.urlparse(artifact_url).path),
            published_at=artifact.get("upload_time_iso_8601"),
            parent_name=coordinate.parent_name,
            dependency_path=coordinate.dependency_path or [coordinate.name],
            depth=coordinate.depth,
            resolution_source=coordinate.resolution_source,
            coverage_mode=coordinate.coverage_mode,
            integrity={
                "status": "pending" if hash_value else "missing",
                "provider": "pypi",
                "kind": "sha256" if digests.get("sha256") else ("md5" if digests.get("md5") else None),
                "value": hash_value,
            },
            extra={"packagetype": artifact.get("packagetype")},
        )

    @staticmethod
    def _pick_artifact(payload: dict, version: str) -> dict | None:
        candidates = payload.get("urls") or payload.get("releases", {}).get(version, [])
        for packagetype in ("sdist", "bdist_wheel"):
            for candidate in candidates:
                if candidate.get("packagetype") == packagetype:
                    return candidate
        return candidates[0] if candidates else None
