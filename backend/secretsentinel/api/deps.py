"""Shared API dependencies and ORM -> schema serializers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterator

from fastapi import Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.config import Settings
from ..core.errors import ErrorCode, SecretSentinelError, safe_message
from ..core.security import ensure_within_allowed_roots
from ..database import get_session_factory
from ..models import Finding, Repository, Scan
from ..schemas import FindingOut, RepositoryOut, ScanOut
from ..services.jobs import ScanJobManager


def get_db() -> Iterator[Session]:
    """Per-request session. Routes MUST use ``Depends(get_db, scope="function")``.

    With FastAPI's default (request) scope, the code after ``yield`` - our
    commit - runs only AFTER the response has been sent, so a client that reads
    immediately after a write can observe stale data. Function scope commits
    before the response leaves the server.
    """
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_jobs(request: Request) -> ScanJobManager:
    return request.app.state.jobs


class Pagination:
    def __init__(self, page: int = Query(1, ge=1, le=100_000), page_size: int = Query(25, ge=1, le=200)):
        self.page = page
        self.page_size = page_size

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


def get_or_404(session: Session, model, entity_id: str):
    obj = session.get(model, entity_id)
    if obj is None:
        raise SecretSentinelError(ErrorCode.NOT_FOUND)
    return obj


def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def path_allowed(path: str, settings: Settings) -> bool:
    from pathlib import Path

    try:
        ensure_within_allowed_roots(Path(path), settings.scan_root_allowlist)
        return True
    except SecretSentinelError:
        return False


def repository_out(session: Session, repo: Repository, settings: Settings) -> RepositoryOut:
    last = session.scalars(
        select(Scan).where(Scan.repository_id == repo.id).order_by(Scan.created_at.desc()).limit(1)
    ).first()
    return RepositoryOut(
        id=repo.id,
        display_name=repo.display_name,
        local_path=repo.canonical_local_path,
        allowed=path_allowed(repo.canonical_local_path, settings),
        created_at=_aware(repo.created_at),
        last_scan_id=last.id if last else None,
        last_scan_status=last.status if last else None,
        last_policy_result=last.policy_result if last else None,
        last_scan_at=_aware(last.created_at) if last else None,
    )


def severity_counts(session: Session, scan_id: str) -> dict[str, int]:
    counts = {k: 0 for k in ("critical", "high", "medium", "low")}
    rows = session.execute(
        select(Finding.severity, func.count()).where(Finding.scan_id == scan_id).group_by(Finding.severity)
    ).all()
    for sev, n in rows:
        counts[sev] = n
    return counts


def scan_out(session: Session, scan: Scan, repo_name: str | None = None) -> ScanOut:
    if repo_name is None:
        repo = session.get(Repository, scan.repository_id)
        repo_name = repo.display_name if repo else "(deleted)"
    started, finished = _aware(scan.started_at), _aware(scan.finished_at)
    duration = int((finished - started).total_seconds() * 1000) if started and finished else None
    try:
        warnings = [str(w) for w in json.loads(scan.warnings_json or "[]")][:50]
    except ValueError:
        warnings = []
    return ScanOut(
        id=scan.id,
        repository_id=scan.repository_id,
        repository_name=repo_name,
        source=scan.source,
        mode=scan.mode,
        status=scan.status,
        policy_result=scan.policy_result,
        fail_on=scan.fail_on or "",
        since_ref=scan.since_ref,
        scope=scan.scope,
        commit_sha=scan.commit_sha,
        scanner_name=scan.scanner_name,
        scanner_version=scan.scanner_version,
        secretsentinel_version=scan.secretsentinel_version,
        ruleset_version=scan.ruleset_version,
        ruleset_digest=scan.ruleset_digest,
        policy_digest=scan.policy_digest,
        created_at=_aware(scan.created_at),
        started_at=started,
        finished_at=finished,
        duration_ms=duration,
        total_findings=scan.total_findings,
        blocking_findings=scan.blocking_findings,
        suppressed_findings=scan.suppressed_findings,
        severity_counts=severity_counts(session, scan.id),
        error_code=scan.error_code,
        error_message=safe_message(scan.error_code),
        warnings=warnings,
    )


def finding_out(f: Finding, scan_mode: str, repo_name: str) -> dict:
    return FindingOut(
        id=f.id,
        scan_id=f.scan_id,
        scan_mode=scan_mode,
        repository_id=f.repository_id,
        repository_name=repo_name,
        fingerprint=f.fingerprint,
        rule_id=f.rule_id,
        rule_family=f.rule_family,
        title=f.title,
        severity=f.severity,
        confidence=f.confidence,
        requirement=f.requirement,
        relative_path=f.relative_path,
        start_line=f.start_line,
        end_line=f.end_line,
        commit_sha=f.commit_sha,
        sources=[s for s in (f.sources or "").split(",") if s],
        also_matched=[s for s in (f.also_matched or "").split(",") if s],
        status=f.status,
        suppression_id=f.suppression_id,
        blocking=f.blocking,
        remediation_key=f.remediation_key,
        first_seen_at=_aware(f.first_seen_at),
        last_seen_at=_aware(f.last_seen_at),
        status_updated_at=_aware(f.status_updated_at),
    ).model_dump()
