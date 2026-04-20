import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from packguard.models import PackageCoordinate, ResolvedPackage, ScanResult
from packguard.reporting.json_report import write_json_report


class ReportingTestCase(unittest.TestCase):
    def test_json_report_writes_summary_and_metadata(self):
        results = [
            ScanResult(
                package=ResolvedPackage(
                    coordinate=PackageCoordinate(name="react", version="1.0.0", source="npm"),
                    coverage_mode="fully-resolved",
                    integrity={"status": "verified"},
                ),
                findings=[],
                risk_score=81,
                verdict="malicious",
                metadata={
                    "artifact_url": "https://registry.npmjs.org/react/-/react-1.0.0.tgz",
                    "coverage_mode": "fully-resolved",
                    "integrity": {"status": "verified"},
                },
            ),
            ScanResult(
                package=ResolvedPackage(
                    coordinate=PackageCoordinate(name="demo", version=None, source="pypi"),
                    coverage_mode="direct-only",
                    integrity={"status": "missing"},
                ),
                findings=[],
                risk_score=20,
                verdict="clean",
                metadata={
                    "coverage_mode": "direct-only",
                    "integrity": {"status": "missing"},
                },
            ),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = os.path.join(tmpdir, "report.json")
            report = write_json_report(results, report_path)

            self.assertEqual(report["total_packages"], 2)
            self.assertEqual(report["malicious_count"], 1)
            self.assertEqual(report["suspicious_count"], 0)
            self.assertEqual(report["coverage_modes"], ["direct-only", "fully-resolved"])
            self.assertTrue(os.path.exists(report_path))


if __name__ == "__main__":
    unittest.main()
