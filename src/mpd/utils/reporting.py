import json
from datetime import datetime
from mpd.models import AnalysisResult

def generate_report(results: list[AnalysisResult], output_path: str = "report.json"):
    report = {
        "timestamp": datetime.now().isoformat(),
        "total_packages": len(results),
        "suspicious_count": sum(1 for r in results if r.suspicious),
        "results": [
            {
                "package": r.package.name,
                "source": r.package.source,
                "suspicious": r.suspicious,
                "reasons": r.reasons
            }
            for r in results
        ]
    }
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    return report
