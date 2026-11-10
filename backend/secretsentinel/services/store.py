"""Persist sanitized scan outcomes and audit events."""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.security import safe_text
from ..models import AuditEvent, Finding, Repository, Scan, Suppression as SuppressionRow
from .policy import Suppression
from .types import ScanOutcome

_SAFE_META_TYPES = (str, int, float, bool, type(None))


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def audit(session: Session, actor: str, action: str, entity_type: str, entity_id: str, **metadata) -> AuditEvent:
    safe = {k: v for k, v in metadata.items() if isinstance(v, _SAFE_META_TYPES)}
    event = AuditEvent(
        actor=safe_text(actor, 120),
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        safe_metadata_json=json.dumps(safe, sort_keys=True),
    )
    session.add(event)
    return event


def get_or_create_repository(session: Session, path: Path, display_name: str | None = None) -> Repository:
    key = str(path)
    repo = session.scalar(select(Repository).where(Repository.canonical_local_path == key))
    if repo is None:
        repo = Repository(display_name=safe_text(display_name or path.name or key, 200), canonical_local_path=key)
        session.add(repo)
        session.flush()
        audit(session, "local-user", "repository.registered", "repository", repo.id)
    return repo


def apply_outcome(session: Session, scan: Scan, outcome: ScanOutcome) -> Scan:
    """Write a completed/failed outcome onto an existing Scan row (+ findings)."""
    scan.status = outcome.status
    scan.policy_result = outcome.policy_result
    scan.fail_on = outcome.fail_on
    scan.scope = outcome.scope or None
    scan.commit_sha = outcome.commit_sha
    scan.scanner_name = outcome.scanner_name
    scan.scanner_version = outcome.scanner_version
    scan.secretsentinel_version = outcome.secretsentinel_version
    scan.ruleset_version = outcome.ruleset_version
    scan.ruleset_digest = outcome.ruleset_digest
    scan.policy_digest = outcome.policy_digest
    scan.started_at = scan.started_at or outcome.started_at
    scan.finished_at = outcome.finished_at
    scan.total_findings = outcome.total_findings
    scan.blocking_findings = outcome.blocking_findings
    scan.suppressed_findings = outcome.suppressed_findings
    scan.error_code = outcome.error_code
    scan.warnings_json = json.dumps([safe_text(w, 200) for w in outcome.warnings][:50])
    seen_at = outcome.finished_at or _utcnow()
    for f in outcome.findings:
        previous = session.execute(
            select(Finding.status, Finding.first_seen_at)
            .where(Finding.repository_id == scan.repository_id, Finding.fingerprint == f.fingerprint, Finding.scan_id != scan.id)
            .order_by(Finding.last_seen_at.desc())
            .limit(1)
        ).first()
        first_seen = session.scalar(
            select(func.min(Finding.first_seen_at)).where(
                Finding.repository_id == scan.repository_id, Finding.fingerprint == f.fingerprint
            )
        )
        status = f.status
        if status != "suppressed" and previous is not None:
            if previous.status == "acknowledged":
                status = "acknowledged"
            # "resolved" findings that are detected again are reopened (status stays open).
        row = Finding(
            scan_id=scan.id,
            repository_id=scan.repository_id,
            fingerprint=f.fingerprint,
            rule_id=f.rule_id,
            rule_family=f.family,
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            requirement=f.requirement,
            relative_path=f.relative_path,
            start_line=f.start_line,
            end_line=f.end_line,
            start_column=f.start_column,
            commit_sha=f.commit_sha,
            entropy=f.entropy,
            sources=",".join(f.sources),
            also_matched=",".join(f.also_matched),
            status=status,
            suppression_id=f.suppression_id,
            blocking=f.blocking,
            remediation_key=f.remediation_key,
            first_seen_at=_aware(first_seen) or seen_at,
            last_seen_at=seen_at,
        )
        session.add(row)
        if previous is not None and previous.status == "resolved" and status == "open":
            session.flush()
            audit(session, "system", "finding.reopened", "finding", row.id, fingerprint=f.fingerprint)
    return scan


def record_outcome(session: Session, repo: Repository, outcome: ScanOutcome, source: str, since_ref: str | None = None) -> Scan:
    scan = Scan(repository_id=repo.id, source=source, mode=outcome.mode, status="running", since_ref=since_ref)
    session.add(scan)
    session.flush()
    apply_outcome(session, scan, outcome)
    audit(session, "local-user" if source == "cli" else "system", "scan.recorded", "scan", scan.id, status=scan.status, source=source)
    return scan


def dashboard_suppressions(session: Session, repository_id: str) -> list[Suppression]:
    rows = session.scalars(
        select(SuppressionRow).where(SuppressionRow.repository_id == repository_id, SuppressionRow.active.is_(True))
    ).all()
    return [
        Suppression(
            id=f"db-{r.id[:8]}",
            rule_id=r.rule_id,
            path=r.path,
            line=r.line,
            commit_sha=r.commit_sha,
            fingerprint=r.fingerprint,
            reason=r.reason,
            reviewer=r.reviewer,
            created=r.created_at.date() if r.created_at else None,
            expires=r.expires_at if isinstance(r.expires_at, date) else None,
            origin="dashboard",
            exact_path=True,
        )
        for r in rows
    ]
