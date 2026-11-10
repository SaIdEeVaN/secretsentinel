"""Assign severity, confidence, family and remediation to sanitized findings.

Classification uses only safe metadata: rule ID, path and entropy. The secret
value is never available here (Gitleaks runs with --redact=100).
"""

from __future__ import annotations

from .rules import Ruleset
from .types import CONFIDENCE_ORDER, SafeFinding

_LOWER = {"high": "medium", "medium": "low", "low": "low"}


def classify(finding: SafeFinding, ruleset: Ruleset) -> SafeFinding:
    meta = ruleset.meta(finding.rule_id)
    finding.title = meta.title
    finding.severity = meta.severity
    finding.family = meta.family
    finding.remediation_key = meta.remediation_key
    finding.requirement = meta.requirement
    confidence = meta.confidence
    # Heuristics may only LOWER confidence; severity (and blocking) is unchanged,
    # because a real key committed under tests/ is still a real key.
    if finding.relative_path and ruleset.is_low_confidence_path(finding.relative_path):
        confidence = _LOWER[confidence]
    if finding.entropy is not None and 0 < finding.entropy < 3.0 and meta.family != "web3-mnemonic":
        confidence = _LOWER[confidence]
    assert confidence in CONFIDENCE_ORDER
    finding.confidence = confidence
    return finding


def classify_all(findings: list[SafeFinding], ruleset: Ruleset) -> list[SafeFinding]:
    return [classify(f, ruleset) for f in findings]
