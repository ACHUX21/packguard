"""Core scan pipeline."""

from __future__ import annotations

import json
import re
from pathlib import Path

from packguard.ai.factory import create_explainer
from packguard.config import Config
from packguard.engine.scoring import score_findings
from packguard.extractors.archive import ArtifactExtractor
from packguard.intel.feed import ThreatFeed
from packguard.intel.popularity import PopularityIndex
from packguard.models import Finding, PackageCoordinate, ResolvedPackage, ScanResult
from packguard.reporting.json_report import write_json_report
from packguard.scanners.behavior import BehaviorScanner
from packguard.scanners.static import StaticScanner
from packguard.scanners.typosquat import TyposquatScanner
from packguard.sources import get_source


class ScanPipeline:
    def __init__(self, config: Config, logger):
        self.config = config
        self.logger = logger
        self.extractor = ArtifactExtractor()
        self.static_scanner = StaticScanner(config)
        self.behavior_scanner = BehaviorScanner()
        self.threat_feed = ThreatFeed(config.malicious_feed_path)
        self.popularity = PopularityIndex(config.popular_packages_path)
        self.typosquat_scanner = TyposquatScanner(config, self.popularity)
        self.explainer = create_explainer(config)

    def scan_package(self, coordinate: PackageCoordinate) -> ScanResult:
        if self.config.offline_mode:
            raise ValueError("offline_mode is enabled: use 'scan archive' for local artifacts")

        if not coordinate.dependency_path:
            coordinate.dependency_path = [coordinate.name]
        if coordinate.depth == 0:
            coordinate.depth = max(1, len(coordinate.dependency_path))
        if coordinate.resolution_source == "package":
            coordinate.resolution_source = "registry"
        if coordinate.coverage_mode == "artifact-only":
            coordinate.coverage_mode = "single-package"

        resolved = get_source(coordinate.source).resolve(coordinate)
        return self._scan_resolved_package(resolved)

    def scan_archive(
        self,
        path: str,
        source: str,
        name: str,
        version: str | None = None,
    ) -> ScanResult:
        coordinate = PackageCoordinate(
            name=name,
            source=source,
            version=version,
            requested_version=version,
            dependency_path=[name],
            depth=0,
            resolution_source="archive",
            coverage_mode="single-package",
            exact=version is not None,
        )
        resolved = ResolvedPackage(
            coordinate=coordinate,
            artifact_path=path,
            artifact_filename=Path(path).name,
            parent_name=None,
            dependency_path=[name],
            depth=0,
            resolution_source="archive",
            coverage_mode="single-package",
            integrity={"status": "not-applicable", "provider": "local"},
        )
        return self._scan_resolved_package(resolved)

    def scan_manifest(self, manifest_path: str, source: str) -> list[ScanResult]:
        if self.config.offline_mode:
            raise ValueError("offline_mode is enabled: use 'scan archive' for local artifacts")

        path = Path(manifest_path)
        if source == "npm":
            if path.name == "package.json":
                package_lock = path.with_name("package-lock.json")
                if package_lock.exists():
                    return self.scan_lockfile(str(package_lock), source="npm")
            if path.name == "package-lock.json":
                return self.scan_lockfile(str(path), source="npm")
            if path.name == "pnpm-lock.yaml":
                raise ValueError("pnpm-lock.yaml scanning is not implemented yet; use package-lock.json")

        coordinates = self._parse_manifest(path, source)
        return [self.scan_package(coordinate) for coordinate in coordinates]

    def scan_lockfile(self, lockfile_path: str, source: str = "npm") -> list[ScanResult]:
        if self.config.offline_mode:
            raise ValueError("offline_mode is enabled: use 'scan archive' for local artifacts")
        if source != "npm":
            raise ValueError("lockfile scanning is currently supported only for npm package-lock.json")

        path = Path(lockfile_path)
        if path.name != "package-lock.json":
            raise ValueError("Only package-lock.json is supported for exact lockfile scanning")

        packages = self._parse_package_lock(path)
        return [self._scan_resolved_package(package) for package in packages]

    def write_report(self, results: list[ScanResult], output_path: str | None = None) -> dict:
        return write_json_report(results, output_path or self.config.output_path)

    def _scan_resolved_package(self, package: ResolvedPackage) -> ScanResult:
        package = self._ensure_resolved_artifact(package)
        self.logger.info(
            "Scanning %s:%s@%s",
            package.coordinate.source,
            package.coordinate.name,
            package.coordinate.version or "unknown",
        )
        extraction = self.extractor.extract(package)
        try:
            findings: list[Finding] = []
            findings.extend(self._build_resolution_findings(package))
            if "threat_feed" in self.config.scanners:
                findings.extend(self.threat_feed.match(package))
            if "typosquat" in self.config.scanners:
                findings.extend(self.typosquat_scanner.scan(package))
            if "behavior" in self.config.scanners:
                findings.extend(self.behavior_scanner.scan(package, extraction))
            if "static" in self.config.scanners:
                findings.extend(self.static_scanner.scan(package, extraction))
            findings.extend(self._build_integrity_findings(package))

            risk_score, verdict = score_findings(findings, self.config)
            ai_summary, ai_status = self.explainer.summarize(package, findings)
            ai_metadata = self.explainer.metadata()
            ai_metadata["status"] = ai_status
            decision_basis = self._decision_basis(findings)

            return ScanResult(
                package=package,
                findings=findings,
                risk_score=risk_score,
                verdict=verdict,
                ai_summary=ai_summary,
                metadata={
                    "artifact_url": package.artifact_url,
                    "artifact_path": package.artifact_path,
                    "metadata_url": package.metadata_url,
                    "published_at": package.published_at,
                    "file_count": len(extraction.files),
                    "coverage_mode": package.coverage_mode,
                    "dependency_parent": package.parent_name,
                    "dependency_path": package.dependency_path,
                    "depth": package.depth,
                    "integrity": package.integrity,
                    "decision_basis": decision_basis,
                    "ai": ai_metadata,
                },
            )
        finally:
            self.extractor.cleanup(extraction)

    def _ensure_resolved_artifact(self, package: ResolvedPackage) -> ResolvedPackage:
        if package.artifact_path or package.artifact_url:
            return package
        if self.config.offline_mode:
            raise ValueError("offline_mode is enabled and this package has no local artifact path")

        resolved = get_source(package.coordinate.source).resolve(package.coordinate)
        resolved.parent_name = package.parent_name or resolved.parent_name
        resolved.dependency_path = package.dependency_path or resolved.dependency_path
        resolved.depth = package.depth or resolved.depth
        resolved.resolution_source = package.resolution_source
        resolved.coverage_mode = package.coverage_mode
        return resolved

    def _build_resolution_findings(self, package: ResolvedPackage) -> list[Finding]:
        findings: list[Finding] = []
        if package.coverage_mode == "direct-only":
            findings.append(
                Finding(
                    rule_id="resolution.direct-only-coverage",
                    title="Direct dependency coverage only",
                    summary="Manifest scan is not fully resolved; transitive dependencies may still be uninspected.",
                    severity="low",
                    confidence="high",
                    family="resolution",
                    phase="resolution",
                    rationale="Without a lockfile, the scanner cannot prove coverage of the exact dependency graph.",
                    detector="resolution",
                    location="package",
                    evidence=[f"coverage_mode={package.coverage_mode}"],
                    tags=["coverage"],
                )
            )

        if package.coordinate.requested_version and package.coordinate.exact is False:
            findings.append(
                Finding(
                    rule_id="resolution.unpinned-request",
                    title="Unpinned package request",
                    summary="Manifest requested a package range or URL instead of an exact version.",
                    severity="low",
                    confidence="high",
                    family="resolution",
                    phase="resolution",
                    rationale="Unpinned package requests make scan results less exact than lockfile-based resolution.",
                    detector="resolution",
                    location="package",
                    evidence=[f"requested_version={package.coordinate.requested_version}"],
                    tags=["pinning"],
                )
            )
        return findings

    def _build_integrity_findings(self, package: ResolvedPackage) -> list[Finding]:
        status = package.integrity.get("status")
        if status not in {"missing", "unsupported"}:
            return []

        summary = (
            "Registry metadata did not provide a usable artifact integrity value."
            if status == "missing"
            else "Artifact integrity metadata used an unsupported hashing scheme."
        )
        rationale = (
            "Missing integrity reduces confidence that the scanned artifact exactly matches registry metadata."
            if status == "missing"
            else "Unsupported integrity metadata prevents Packguard from verifying the downloaded artifact."
        )
        return [
            Finding(
                rule_id=f"trust.{status}-integrity",
                title="Artifact integrity not verified",
                summary=summary,
                severity="medium" if status == "missing" else "low",
                confidence="medium",
                family="trust",
                phase="resolution",
                rationale=rationale,
                detector="trust",
                location="package",
                evidence=[f"integrity_status={status}"],
                tags=["integrity"],
            )
        ]

    def _decision_basis(self, findings: list[Finding]) -> str:
        detectors = {finding.detector for finding in findings}
        if "intel" in detectors and len(detectors) > 1:
            return "intel+heuristic"
        if "intel" in detectors:
            return "intel"
        if detectors:
            return "heuristic"
        return "none"

    def _parse_manifest(self, path: Path, source: str) -> list[PackageCoordinate]:
        if source == "npm":
            return self._parse_package_manifest(path)
        return self._parse_requirements(path)

    def _parse_package_manifest(self, path: Path) -> list[PackageCoordinate]:
        payload = json.loads(path.read_text(encoding="utf-8"))
        coordinates = []
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, version_spec in payload.get(section, {}).items():
                exact_version = _normalize_npm_version(version_spec)
                coordinates.append(
                    PackageCoordinate(
                        name=name,
                        source="npm",
                        version=exact_version,
                        requested_version=version_spec,
                        parent_name=None,
                        dependency_path=[name],
                        depth=1,
                        resolution_source="manifest",
                        coverage_mode="direct-only",
                        exact=exact_version is not None,
                    )
                )
        return coordinates

    def _parse_requirements(self, path: Path) -> list[PackageCoordinate]:
        coordinates = []
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            name, version, exact = _parse_requirement_line(stripped)
            coordinates.append(
                PackageCoordinate(
                    name=name,
                    source="pypi",
                    version=version,
                    requested_version=stripped,
                    parent_name=None,
                    dependency_path=[name],
                    depth=1,
                    resolution_source="manifest",
                    coverage_mode="direct-only",
                    exact=exact,
                )
            )
        return coordinates

    def _parse_package_lock(self, path: Path) -> list[ResolvedPackage]:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if "packages" in payload:
            return self._parse_lockfile_packages_map(payload["packages"])
        return self._parse_lockfile_dependency_tree(payload.get("dependencies", {}))

    def _parse_lockfile_packages_map(self, packages_payload: dict) -> list[ResolvedPackage]:
        resolved_packages: list[ResolvedPackage] = []
        for lock_path, entry in packages_payload.items():
            if lock_path == "":
                continue
            dependency_path = _dependency_chain_from_lock_path(lock_path)
            name = entry.get("name") or (dependency_path[-1] if dependency_path else None)
            version = entry.get("version")
            if not name or not version:
                continue
            coordinate = PackageCoordinate(
                name=name,
                source="npm",
                version=version,
                requested_version=version,
                parent_name=dependency_path[-2] if len(dependency_path) > 1 else None,
                dependency_path=dependency_path or [name],
                depth=max(1, len(dependency_path or [name])),
                resolution_source="lockfile",
                coverage_mode="fully-resolved",
                exact=True,
            )
            resolved_packages.append(
                ResolvedPackage(
                    coordinate=coordinate,
                    artifact_url=entry.get("resolved"),
                    artifact_filename=_artifact_filename(entry.get("resolved")),
                    parent_name=coordinate.parent_name,
                    dependency_path=coordinate.dependency_path,
                    depth=coordinate.depth,
                    resolution_source="lockfile",
                    coverage_mode="fully-resolved",
                    integrity={
                        "status": "pending" if entry.get("integrity") else "missing",
                        "provider": "package-lock",
                        "kind": "sri" if entry.get("integrity") else None,
                        "value": entry.get("integrity"),
                    },
                    extra={"dev": entry.get("dev", False), "optional": entry.get("optional", False)},
                )
            )
        return resolved_packages

    def _parse_lockfile_dependency_tree(self, dependencies: dict, parent_path: list[str] | None = None) -> list[ResolvedPackage]:
        resolved_packages: list[ResolvedPackage] = []
        parent_path = parent_path or []
        for name, entry in dependencies.items():
            dependency_path = [*parent_path, name]
            coordinate = PackageCoordinate(
                name=name,
                source="npm",
                version=entry.get("version"),
                requested_version=entry.get("version"),
                parent_name=dependency_path[-2] if len(dependency_path) > 1 else None,
                dependency_path=dependency_path,
                depth=len(dependency_path),
                resolution_source="lockfile",
                coverage_mode="fully-resolved",
                exact=True,
            )
            resolved_packages.append(
                ResolvedPackage(
                    coordinate=coordinate,
                    artifact_url=entry.get("resolved"),
                    artifact_filename=_artifact_filename(entry.get("resolved")),
                    parent_name=coordinate.parent_name,
                    dependency_path=dependency_path,
                    depth=len(dependency_path),
                    resolution_source="lockfile",
                    coverage_mode="fully-resolved",
                    integrity={
                        "status": "pending" if entry.get("integrity") else "missing",
                        "provider": "package-lock",
                        "kind": "sri" if entry.get("integrity") else None,
                        "value": entry.get("integrity"),
                    },
                )
            )
            resolved_packages.extend(
                self._parse_lockfile_dependency_tree(entry.get("dependencies", {}), dependency_path)
            )
        return resolved_packages


def _normalize_npm_version(version_spec: str) -> str | None:
    cleaned = version_spec.strip()
    if not cleaned:
        return None
    if re.fullmatch(r"\d+(?:\.\d+){0,2}(?:[-+][A-Za-z0-9.-]+)?", cleaned):
        return cleaned
    if cleaned.startswith("="):
        return cleaned.lstrip("=")
    return None


def _parse_requirement_line(line: str) -> tuple[str, str | None, bool]:
    stripped = line.split("#", 1)[0].strip()
    requirement, _, _marker = stripped.partition(";")

    if " @ " in requirement:
        name, _, _url = requirement.partition(" @ ")
        return _strip_extras(name.strip()), None, False

    for marker in ("==", ">=", "<=", "~=", ">", "<"):
        if marker in requirement:
            name, _, version = requirement.partition(marker)
            return _strip_extras(name.strip()), (version.strip() if marker == "==" else None), marker == "=="

    return _strip_extras(requirement.strip()), None, False


def _strip_extras(name: str) -> str:
    return name.split("[", 1)[0].strip()


def _dependency_chain_from_lock_path(lock_path: str) -> list[str]:
    segments = [segment for segment in lock_path.split("/") if segment]
    packages: list[str] = []
    index = 0
    while index < len(segments):
        if segments[index] != "node_modules":
            index += 1
            continue
        if index + 1 >= len(segments):
            break
        if segments[index + 1].startswith("@") and index + 2 < len(segments):
            packages.append(f"{segments[index + 1]}/{segments[index + 2]}")
            index += 3
        else:
            packages.append(segments[index + 1])
            index += 2
    return packages


def _artifact_filename(url: str | None) -> str | None:
    if not url:
        return None
    return Path(url.split("?", 1)[0]).name
