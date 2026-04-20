"""npm source resolution."""

from __future__ import annotations

import json
import os
from urllib import parse, request

from packguard.errors import SourceError
from packguard.models import PackageCoordinate, ResolvedPackage
from packguard.sources.base import PackageSource


class NpmSource(PackageSource):
    def resolve(self, coordinate: PackageCoordinate) -> ResolvedPackage:
        encoded_name = parse.quote(coordinate.name, safe="@/")
        metadata_url = f"https://registry.npmjs.org/{encoded_name}"

        try:
            with request.urlopen(metadata_url, timeout=30) as response:
                payload = json.load(response)
        except Exception as exc:
            raise SourceError(
                f"Failed to fetch npm metadata for '{coordinate.name}': {exc}"
            ) from exc

        version = coordinate.version or payload.get("dist-tags", {}).get("latest")
        if not version:
            raise SourceError(f"Could not determine version for npm package '{coordinate.name}'")

        version_payload = payload.get("versions", {}).get(version)
        if not version_payload:
            raise SourceError(
                f"Version '{version}' was not found for npm package '{coordinate.name}'"
            )

        tarball_url = version_payload.get("dist", {}).get("tarball")
        if not tarball_url:
            raise SourceError(
                f"Could not determine tarball URL for npm package '{coordinate.name}'"
            )

        coordinate.version = version
        integrity_value = version_payload.get("dist", {}).get("integrity")
        shasum_value = version_payload.get("dist", {}).get("shasum")
        return ResolvedPackage(
            coordinate=coordinate,
            metadata_url=metadata_url,
            artifact_url=tarball_url,
            artifact_filename=os.path.basename(parse.urlparse(tarball_url).path),
            published_at=payload.get("time", {}).get(version),
            parent_name=coordinate.parent_name,
            dependency_path=coordinate.dependency_path or [coordinate.name],
            depth=coordinate.depth,
            resolution_source=coordinate.resolution_source,
            coverage_mode=coordinate.coverage_mode,
            integrity={
                "status": "pending" if (integrity_value or shasum_value) else "missing",
                "provider": "npm",
                "kind": "sri" if integrity_value else ("sha1" if shasum_value else None),
                "value": integrity_value or shasum_value,
            },
            extra={"dist_integrity": integrity_value, "shasum": shasum_value},
        )
