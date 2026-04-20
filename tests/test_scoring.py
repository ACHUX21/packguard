import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from packguard.config import Config
from packguard.engine.scoring import score_findings
from packguard.models import Finding


class ScoringTestCase(unittest.TestCase):
    def test_exact_intel_hit_forces_malicious(self):
        findings = [
            Finding(
                rule_id="threat-feed.known-malware",
                title="Known malicious package version",
                summary="exact hit",
                severity="critical",
                confidence="high",
                family="intel",
                phase="resolution",
                rationale="exact match",
                detector="intel",
                location="package",
            )
        ]

        score, verdict = score_findings(findings, Config())
        self.assertEqual(score, 100)
        self.assertEqual(verdict, "malicious")

    def test_correlated_findings_escalate_without_unbounded_duplication(self):
        findings = [
            Finding(
                rule_id="behavior.install-script",
                title="Install-time script",
                summary="runs during install",
                severity="high",
                confidence="high",
                family="behavior",
                phase="install",
                rationale="install-time execution",
                detector="behavior",
                location="package.json",
                tags=["loader"],
            ),
            Finding(
                rule_id="static.download-exec-chain",
                title="Download and execute",
                summary="curl | bash",
                severity="high",
                confidence="high",
                family="static",
                phase="install",
                rationale="loader chain",
                detector="static",
                location="package.json",
            ),
            Finding(
                rule_id="static.download-exec-chain",
                title="Download and execute",
                summary="curl | bash",
                severity="high",
                confidence="high",
                family="static",
                phase="install",
                rationale="duplicate signal",
                detector="static",
                location="package.json",
            ),
        ]

        score, verdict = score_findings(findings, Config())
        self.assertGreaterEqual(score, 75)
        self.assertEqual(verdict, "malicious")


if __name__ == "__main__":
    unittest.main()
