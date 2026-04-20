"""Offline malicious package feed loader."""

from __future__ import annotations

import json
from pathlib import Path

from packguard.models import Finding, ResolvedPackage


class ThreatFeed:
    def __init__(self, path: str):
        self.path = Path(path)
        self._entries = self._load_entries()

    def match(self, package: ResolvedPackage) -> list[Finding]:
        package_name = package.coordinate.name.lower()
        package_version = (package.coordinate.version or "").lower()
        findings: list[Finding] = []
        for entry in self._entries:
            if entry["source"] != package.coordinate.source:
                continue
            if entry["name"].lower() != package_name:
                continue
            if entry["version"].lower() != package_version:
                continue
            findings.append(
                Finding(
                    rule_id="threat-feed.known-malware",
                    title="Known malicious package version",
                    summary=entry["summary"],
                    severity="critical",
                    confidence="high",
                    family="intel",
                    phase="resolution",
                    rationale="This package/version exactly matches the local malicious-package intelligence snapshot.",
                    detector="intel",
                    location="package",
                    evidence=entry.get("references", []),
                    tags=["intel", "known-malware"],
                )
            )
        return findings

    def snapshot_info(self) -> dict:
        if not self.path.exists():
            return {"path": str(self.path), "updated_at": None, "entry_count": 0}
        stat = self.path.stat()
        return {
            "path": str(self.path),
            "updated_at": stat.st_mtime,
            "entry_count": len(self._entries),
        }

    def _load_entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        return json.loads(self.path.read_text(encoding="utf-8"))
