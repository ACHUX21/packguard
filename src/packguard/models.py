"""Shared dataclasses used throughout the scan pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class PackageCoordinate:
    name: str
    source: str
    version: str | None = None
    requested_version: str | None = None
    parent_name: str | None = None
    dependency_path: list[str] = field(default_factory=list)
    depth: int = 0
    resolution_source: str = "package"
    coverage_mode: str = "artifact-only"
    exact: bool | None = None


@dataclass(slots=True)
class ResolvedPackage:
    coordinate: PackageCoordinate
    metadata_url: str | None = None
    artifact_url: str | None = None
    artifact_filename: str | None = None
    artifact_path: str | None = None
    published_at: str | None = None
    parent_name: str | None = None
    dependency_path: list[str] = field(default_factory=list)
    depth: int = 0
    resolution_source: str = "package"
    coverage_mode: str = "artifact-only"
    integrity: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ExtractionResult:
    root_dir: Path
    files: list[Path]
    metadata_files: list[Path]


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    summary: str
    severity: str
    confidence: str
    family: str
    phase: str
    rationale: str
    detector: str
    location: str
    evidence: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    package: ResolvedPackage
    findings: list[Finding]
    risk_score: int
    verdict: str
    metadata: dict[str, Any] = field(default_factory=dict)
    ai_summary: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "package": {
                "name": self.package.coordinate.name,
                "source": self.package.coordinate.source,
                "version": self.package.coordinate.version,
                "requested_version": self.package.coordinate.requested_version,
                "parent": self.package.parent_name,
                "dependency_path": self.package.dependency_path,
                "depth": self.package.depth,
                "resolution_source": self.package.resolution_source,
                "coverage_mode": self.package.coverage_mode,
            },
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "metadata": self.metadata,
            "findings": [finding.to_dict() for finding in self.findings],
            "ai_summary": self.ai_summary,
        }
        return payload
