"""JSON report writer."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from packguard.models import ScanResult


def write_json_report(results: list[ScanResult], output_path: str) -> dict:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_packages": len(results),
        "malicious_count": sum(1 for result in results if result.verdict == "malicious"),
        "suspicious_count": sum(1 for result in results if result.verdict == "suspicious"),
        "coverage_modes": sorted({result.package.coverage_mode for result in results}),
        "results": [result.to_dict() for result in results],
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload
