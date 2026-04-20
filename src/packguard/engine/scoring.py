"""Translate findings into a stable risk score and verdict."""

from __future__ import annotations

from collections import defaultdict

from packguard.config import Config
from packguard.models import Finding


SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 24,
    "medium": 12,
    "low": 5,
}

CONFIDENCE_BONUS = {
    "high": 8,
    "medium": 4,
    "low": 0,
}

FAMILY_CAPS = {
    "intel": 100,
    "behavior": 40,
    "static": 34,
    "name": 20,
    "trust": 18,
    "resolution": 12,
}


def score_findings(findings: list[Finding], config: Config) -> tuple[int, str]:
    if any(f.rule_id == "threat-feed.known-malware" for f in findings):
        return 100, "malicious"

    family_scores: dict[str, int] = defaultdict(int)
    seen = set()
    for finding in findings:
        dedupe_key = (finding.rule_id, finding.location)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        family_scores[finding.family] += SEVERITY_WEIGHTS.get(finding.severity, 0)
        family_scores[finding.family] += CONFIDENCE_BONUS.get(finding.confidence, 0)

    score = 0
    for family, subtotal in family_scores.items():
        score += min(subtotal, FAMILY_CAPS.get(family, subtotal))

    score += _combo_escalation(findings)
    score = min(score, 100)

    if score >= config.risk_thresholds["malicious"]:
        return score, "malicious"
    if score >= config.risk_thresholds["suspicious"]:
        return score, "suspicious"
    return score, "clean"


def _combo_escalation(findings: list[Finding]) -> int:
    rule_ids = {finding.rule_id for finding in findings}
    tags = {tag for finding in findings for tag in finding.tags}
    score = 0

    if "behavior.install-script" in rule_ids and (
        "static.download-exec-chain" in rule_ids
        or "static.network-and-exec" in rule_ids
        or "loader" in tags
    ):
        score += 18

    if "behavior.python-startup-hook" in rule_ids and (
        "static.credential-harvest" in rule_ids
        or "static.sensitive-path-access" in rule_ids
        or "static.python-secret-exfil-intent" in rule_ids
    ):
        score += 16

    if "static.native-binary" in rule_ids and (
        "static.exec-eval" in rule_ids
        or "static.download-exec-chain" in rule_ids
        or "static.obfuscated-blob" in rule_ids
    ):
        score += 12

    if "trust.missing-integrity" in rule_ids and (
        "behavior.install-script" in rule_ids or "static.download-exec-chain" in rule_ids
    ):
        score += 10

    return score
