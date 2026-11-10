"""Export persisted, sanitized findings through the same serializers as the CLI."""

from __future__ import annotations

import json
from datetime import timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.security import safe_text
from ..models import Finding, Scan
from .types import SafeFinding, ScanOutcome


def stored_outcome(session: Session, scan: Scan) -> ScanOutcome:
    """Explicit projection: never serialize ORM objects or raw scanner reports."""
    def aware(value):
        return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value

    outcome = ScanOutcome(
        mode=scan.mode, status=scan.status, policy_result=scan.policy_result,
        fail_on=scan.fail_on or "high", scanner_name=scan.scanner_name,
        scanner_version=scan.scanner_version, secretsentinel_version=scan.secretsentinel_version,
        ruleset_version=scan.ruleset_version, ruleset_digest=scan.ruleset_digest,
        policy_digest=scan.policy_digest, commit_sha=scan.commit_sha, scope=scan.scope or "",
        started_at=aware(scan.started_at), finished_at=aware(scan.finished_at),
        error_code=scan.error_code,
    )
    warnings = json.loads(scan.warnings_json or "[]")
    outcome.warnings = [safe_text(w, 200) for w in warnings[:50]]
    rows = session.scalars(
        select(Finding).where(Finding.scan_id == scan.id)
        .order_by(Finding.relative_path, Finding.start_line, Finding.rule_id, Finding.id)
    )
    outcome.findings = [
        SafeFinding(
            rule_id=f.rule_id, relative_path=f.relative_path,
            start_line=f.start_line, end_line=f.end_line, start_column=f.start_column,
            commit_sha=f.commit_sha, entropy=f.entropy,
            sources=tuple(filter(None, (f.sources or "").split(","))),
            also_matched=tuple(filter(None, (f.also_matched or "").split(","))),
            title=f.title, severity=f.severity, confidence=f.confidence,
            family=f.rule_family, remediation_key=f.remediation_key, requirement=f.requirement,
            status=f.status, suppression_id=f.suppression_id, blocking=f.blocking,
        )
        for f in rows
    ]
    return outcome
