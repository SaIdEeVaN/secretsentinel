"""In-memory result types shared by the CLI, API and exporters.

These types carry ONLY sanitized metadata. There is intentionally no field
that could hold a secret, a match, or a source line.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
CONFIDENCE_ORDER = {"high": 3, "medium": 2, "low": 1}

SCAN_STATUSES = ("queued", "running", "completed", "failed", "cancelled")
POLICY_RESULTS = ("pass", "fail", "not_evaluated")
FINDING_STATUSES = ("open", "acknowledged", "resolved", "suppressed")
SCAN_MODES = ("dir", "git", "both", "ci")


def location_fingerprint(rule_id: str, path: str, start_line: int, commit_sha: str | None) -> str:
    """Stable, non-secret identifier derived only from rule + location metadata.

    Never derived from the secret value (PRD 10.3): low-entropy secrets hashed
    without a key could be guessed offline.
    """
    material = "\x00".join([rule_id, path, str(start_line), commit_sha or ""])
    return "ss1:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


@dataclass
class SafeFinding:
    rule_id: str
    relative_path: str
    start_line: int
    end_line: int
    start_column: int = 0
    end_column: int = 0
    commit_sha: str | None = None
    entropy: float | None = None
    tags: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    also_matched: tuple[str, ...] = ()
    # classification
    title: str = ""
    severity: str = "high"
    confidence: str = "medium"
    family: str = "service-credential"
    remediation_key: str = "REVIEW_GENERIC_SECRET"
    requirement: str | None = None
    # policy
    status: str = "open"
    suppression_id: str | None = None
    blocking: bool = False

    @property
    def fingerprint(self) -> str:
        return location_fingerprint(self.rule_id, self.relative_path, self.start_line, self.commit_sha)

    def to_safe_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "title": self.title,
            "rule_family": self.family,
            "severity": self.severity,
            "confidence": self.confidence,
            "requirement": self.requirement,
            "relative_path": self.relative_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_column": self.start_column,
            "commit_sha": self.commit_sha,
            "entropy": self.entropy,
            "sources": list(self.sources),
            "also_matched": list(self.also_matched),
            "status": self.status,
            "suppression_id": self.suppression_id,
            "blocking": self.blocking,
            "remediation_key": self.remediation_key,
        }


@dataclass
class ScanOutcome:
    mode: str
    status: str = "running"
    error_code: str | None = None
    policy_result: str = "not_evaluated"
    fail_on: str = "high"
    scanner_name: str = "gitleaks"
    scanner_version: str | None = None
    secretsentinel_version: str | None = None
    ruleset_version: str | None = None
    ruleset_digest: str | None = None
    policy_digest: str | None = None
    commit_sha: str | None = None
    scope: str = ""
    started_at: datetime | None = None
    finished_at: datetime | None = None
    findings: list[SafeFinding] = field(default_factory=list)
    dropped_fields: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def blocking_findings(self) -> int:
        return sum(1 for f in self.findings if f.blocking)

    @property
    def suppressed_findings(self) -> int:
        return sum(1 for f in self.findings if f.status == "suppressed")

    def severity_counts(self) -> dict[str, int]:
        counts = {k: 0 for k in ("critical", "high", "medium", "low")}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
