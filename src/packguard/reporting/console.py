"""Console rendering."""

from __future__ import annotations

from packguard.models import ScanResult


def render_console_summary(results: list[ScanResult]) -> str:
    lines = []
    for result in results:
        package = result.package.coordinate
        integrity_status = result.metadata.get("integrity", {}).get("status", "unknown")
        coverage_mode = result.metadata.get("coverage_mode", result.package.coverage_mode)
        lines.append(
            f"{package.source}:{package.name}@{package.version or 'unknown'} -> "
            f"{result.verdict.upper()} (score={result.risk_score}, coverage={coverage_mode}, integrity={integrity_status})"
        )
        for finding in result.findings[:5]:
            lines.append(
                f"  - {finding.severity}: {finding.title} [{finding.location}] "
                f"({finding.family}/{finding.phase})"
            )
        if result.ai_summary:
            lines.append(f"  AI: {result.ai_summary}")
    return "\n".join(lines)
