"""Dashboard metrics, rules metadata, system status and audit log."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import __version__
from ..core.config import Settings
from ..core.errors import ErrorCode, SecretSentinelError
from ..models import AuditEvent, Finding, Repository, Scan
from ..schemas import AuditEventOut, MetricsOverview, RulesResponse, SystemStatus
from ..services.rules import load_ruleset
from ..services.scanner import gitleaks_version, resolve_executable
from .deps import _aware, get_db, get_settings, scan_out
from .routes_findings import latest_completed_scan_ids

router = APIRouter(tags=["metrics"])


@router.get("/metrics/overview", response_model=MetricsOverview)
def overview(session: Session = Depends(get_db)):
    latest_ids = latest_completed_scan_ids(session) or [""]
    current = select(Finding).where(Finding.scan_id.in_(latest_ids))
    open_q = current.where(Finding.status.in_(("open", "acknowledged")))
    severity = {k: 0 for k in ("critical", "high", "medium", "low")}
    for sev, n in session.execute(
        select(Finding.severity, func.count()).where(Finding.scan_id.in_(latest_ids), Finding.status.in_(("open", "acknowledged"))).group_by(Finding.severity)
    ).all():
        severity[sev] = n
    families: dict[str, int] = {}
    for fam, n in session.execute(
        select(Finding.rule_family, func.count()).where(Finding.scan_id.in_(latest_ids), Finding.status.in_(("open", "acknowledged"))).group_by(Finding.rule_family)
    ).all():
        families[fam] = n
    recent = session.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(8)).all()
    trend_rows = session.execute(
        select(Scan, Repository.display_name)
        .join(Repository, Scan.repository_id == Repository.id)
        .where(Scan.status.in_(("completed", "failed")))
        .order_by(Scan.created_at.desc())
        .limit(30)
    ).all()
    trend = [
        {
            "scan_id": s.id,
            "created_at": _aware(s.created_at),
            "repository_name": name,
            "mode": s.mode,
            "status": s.status,
            "policy_result": s.policy_result,
            "total_findings": s.total_findings,
            "blocking_findings": s.blocking_findings,
        }
        for s, name in reversed(trend_rows)
    ]
    return MetricsOverview(
        repositories=session.scalar(select(func.count()).select_from(Repository)) or 0,
        scans_total=session.scalar(select(func.count()).select_from(Scan)) or 0,
        scans_completed=session.scalar(select(func.count()).where(Scan.status == "completed")) or 0,
        scans_failed=session.scalar(select(func.count()).where(Scan.status == "failed")) or 0,
        open_findings=session.scalar(select(func.count()).select_from(open_q.subquery())) or 0,
        blocking_open_findings=session.scalar(
            select(func.count()).select_from(open_q.where(Finding.blocking.is_(True)).subquery())
        )
        or 0,
        severity_counts=severity,
        family_counts=families,
        latest_scans=[scan_out(session, s) for s in recent],
        trend=trend,
    )


@router.get("/rules", response_model=RulesResponse)
def rules():
    rs = load_ruleset()
    return RulesResponse(
        ruleset_version=rs.version,
        ruleset_digest=rs.digest,
        default_severity=rs.defaults["severity"],
        rules=[r.as_dict() for r in rs.list_rules()],
        low_confidence_paths=list(rs.low_confidence_paths),
    )


@router.get("/system/status", response_model=SystemStatus)
def system_status(settings: Settings = Depends(get_settings)):
    scanner = {"available": False, "version": None, "error_code": None, "message": None}
    try:
        path = resolve_executable(settings.gitleaks_path, ErrorCode.SCANNER_NOT_FOUND)
        scanner["version"] = gitleaks_version(path)
        scanner["available"] = True
    except SecretSentinelError as exc:
        scanner["error_code"] = exc.code.value
        scanner["message"] = exc.message
    try:
        resolve_executable(settings.git_path, ErrorCode.GIT_NOT_FOUND)
        git_ok = True
    except SecretSentinelError:
        git_ok = False
    try:
        rs = load_ruleset()
        rv, rd = rs.version, rs.digest
    except SecretSentinelError:
        rv = rd = None
    return SystemStatus(
        version=__version__,
        app_env=settings.app_env,
        scanner=scanner,
        git_available=git_ok,
        ruleset_version=rv,
        ruleset_digest=rd,
        allowed_roots=[str(r) for r in settings.scan_root_allowlist],
        default_fail_on=settings.default_fail_on,
        timeout_seconds=settings.scanner_timeout_seconds,
        max_file_mb=settings.max_scan_file_mb,
        max_concurrent_scans=settings.max_concurrent_scans,
        auth_required=bool(settings.api_token),
        blockchain_enabled=settings.enable_blockchain,
    )


@router.get("/audit-events", response_model=list[AuditEventOut])
def audit_events(
    entity_id: str | None = Query(None, max_length=64),
    limit: int = Query(100, ge=1, le=500),
    session: Session = Depends(get_db),
):
    q = select(AuditEvent).order_by(AuditEvent.occurred_at.desc()).limit(limit)
    if entity_id:
        q = q.where(AuditEvent.entity_id == entity_id)
    out = []
    for e in session.scalars(q).all():
        try:
            meta = json.loads(e.safe_metadata_json or "{}")
        except ValueError:
            meta = {}
        out.append(
            AuditEventOut(
                id=e.id, actor=e.actor, action=e.action, entity_type=e.entity_type,
                entity_id=e.entity_id, occurred_at=_aware(e.occurred_at), metadata=meta,
            )
        )
    return out
