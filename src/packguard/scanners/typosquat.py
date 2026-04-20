"""Typosquat and namespace-confusion detection."""

from __future__ import annotations

from packguard.config import Config
from packguard.intel.popularity import PopularityIndex
from packguard.models import Finding, ResolvedPackage


class TyposquatScanner:
    def __init__(self, config: Config, popularity: PopularityIndex):
        self.config = config
        self.popularity = popularity

    def scan(self, package: ResolvedPackage) -> list[Finding]:
        findings: list[Finding] = []
        normalized_name = self._normalize(package.coordinate.name)

        best_match: tuple[int, str] | None = None
        for protected_name in self._protected_names():
            normalized_protected = self._normalize(protected_name)
            if normalized_name == normalized_protected:
                continue
            distance = self._levenshtein(normalized_name, normalized_protected)
            if distance <= self.config.typosquat_distance and (
                best_match is None or distance < best_match[0]
            ):
                best_match = (distance, protected_name)

        if best_match is not None:
            distance, protected_name = best_match
            findings.append(
                Finding(
                    rule_id="name.typosquat",
                    title="Possible typosquat",
                    summary="Package name is extremely close to a protected dependency name.",
                    severity="high",
                    confidence="medium",
                    family="name",
                    phase="resolution",
                    rationale="Edit-distance collisions are a common package-impersonation tactic.",
                    detector="name",
                    location="package",
                    evidence=[
                        f"'{package.coordinate.name}' is {distance} edit(s) away from protected package '{protected_name}'"
                    ],
                    tags=["typosquat"],
                )
            )

        if package.coordinate.source == "npm" and package.coordinate.name.startswith("@"):
            scope, _, bare_name = package.coordinate.name.partition("/")
            protected_match = self._best_protected_match(bare_name)
            if (
                bare_name
                and protected_match is not None
                and scope not in set(self.config.trusted_scopes)
            ):
                findings.append(
                    Finding(
                        rule_id="name.scope-confusion",
                        title="Scoped package mimics protected dependency",
                        summary="Scoped package reuses or closely mimics a protected dependency name under an untrusted scope.",
                        severity="medium",
                        confidence="medium",
                        family="name",
                        phase="resolution",
                        rationale="Unexpected scopes can impersonate public or internal dependencies during resolution.",
                        detector="name",
                        location="package",
                        evidence=[
                            f"Scope '{scope}' is not trusted and the bare package '{bare_name}' resembles '{protected_match}'"
                        ],
                        tags=["namespace", "dependency-confusion"],
                    )
                )
        return findings

    def _best_protected_match(self, name: str) -> str | None:
        normalized_name = self._normalize(name)
        for protected_name in self._protected_names():
            if self._levenshtein(normalized_name, self._normalize(protected_name)) <= self.config.typosquat_distance:
                return protected_name
        return None

    def _protected_names(self) -> list[str]:
        protected = list(self.popularity.packages)
        for namespace in self.config.private_namespaces:
            protected.append(namespace.rsplit("/", 1)[-1])
        return protected

    @staticmethod
    def _normalize(name: str) -> str:
        value = name.strip().lower()
        if "/" in value:
            value = value.rsplit("/", 1)[-1]
        return value.replace("_", "-").replace(".", "-")

    @staticmethod
    def _levenshtein(left: str, right: str) -> int:
        previous_row = list(range(len(right) + 1))
        for i, left_char in enumerate(left, start=1):
            current_row = [i]
            for j, right_char in enumerate(right, start=1):
                insertions = previous_row[j] + 1
                deletions = current_row[j - 1] + 1
                substitutions = previous_row[j - 1] + (left_char != right_char)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]
