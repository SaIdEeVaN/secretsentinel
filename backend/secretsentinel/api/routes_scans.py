"""Scan lifecycle: start, list, inspect, cancel."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.config import Settings
from ..core.errors import ErrorCode, SecretSentinelError
from ..core.security import canonicalize_existing_dir, ensure_within_allowed_roots, validate_ref_syntax
from ..models import Finding, Repository, Scan
from ..schemas import FindingOut, Page, ScanCreate, ScanCreated, ScanOut
from ..services.jobs import ScanJobManager
from ..services.exporters import to_csv, to_json, to_sarif
from ..services.reports import stored_outcome
from ..services.store import audit
from .deps import Pagination, finding_out, get_db, get_jobs, get_or_404, get_settings, scan_out
from .routes_findings import SEVERITY_RANK, apply_finding_filters

router = APIRouter(tags=["scans"])


@router.post("/scans", response_model=ScanCreated, status_code=status.HTTP_202_ACCEPTED)
def start_scan(
    body: ScanCreate,
    session: Session = Depends(get_db, scope="function"),
    settings: Settings = Depends(get_settings),
    jobs: ScanJobManager = Depends(get_jobs),
):
    repo = get_or_404(session, Repository, body.repository_id)
    # Validate now for a fast, clear error; the worker validates again at start.
    target = canonicalize_existing_dir(repo.canonical_local_path)
    ensure_within_allowed_roots(target, settings.scan_root_allowlist)
    if body.since_ref:
        if body.mode == "dir":
            raise SecretSentinelError(ErrorCode.VALIDATION_ERROR, "since_ref applies to git/both modes only.")
        validate_ref_syntax(body.since_ref)
    active = session.scalar(
        select(Scan.id).where(Scan.repository_id == repo.id, Scan.status.in_(("queued", "running"))).limit(1)
    )
    if active:
        raise SecretSentinelError(ErrorCode.SCAN_ALREADY_RUNNING)
    scan = Scan(
        repository_id=repo.id,
        source="api",
        mode=body.mode,
        status="queued",
        since_ref=body.since_ref,
        fail_on=body.fail_on,
    )
    session.add(scan)
    session.flush()
    audit(session, "local-user", "scan.requested", "scan", scan.id, mode=body.mode)
    session.commit()
    jobs.submit(scan.id)
    return ScanCreated(scan_id=scan.id, status="queued")


@router.get("/scans", response_model=Page[ScanOut])
def list_scans(
    repository_id: str | None = Query(None, max_length=36),
    status_: str | None = Query(None, alias="status", pattern="^(queued|running|completed|failed|cancelled)$"),
    mode: str | None = Query(None, pattern="^(dir|git|both|ci)$"),
    policy_result: str | None = Query(None, pattern="^(pass|fail|not_evaluated)$"),
    pager: Pagination = Depends(),
    session: Session = Depends(get_db, scope="function"),
):
    q = select(Scan)
    if repository_id:
        q = q.where(Scan.repository_id == repository_id)
    if status_:
        q = q.where(Scan.status == status_)
    if mode:
        q = q.where(Scan.mode == mode)
    if policy_result:
        q = q.where(Scan.policy_result == policy_result)
    total = session.scalar(select(func.count()).select_from(q.subquery()))
    rows = session.scalars(q.order_by(Scan.created_at.desc()).offset(pager.offset).limit(pager.page_size)).all()
    return Page[ScanOut](items=[scan_out(session, s) for s in rows], total=total or 0, page=pager.page, page_size=pager.page_size)


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, session: Session = Depends(get_db, scope="function")):
    return scan_out(session, get_or_404(session, Scan, scan_id))


@router.get("/scans/{scan_id}/export")
def export_scan(
    scan_id: str,
    format: Literal["json", "csv", "sarif"] = "json",
    session: Session = Depends(get_db, scope="function"),
):
    scan = get_or_404(session, Scan, scan_id)
    if scan.status != "completed":
        raise SecretSentinelError(ErrorCode.INVALID_STATE, "Only completed scans can be exported.")
    repo = get_or_404(session, Repository, scan.repository_id)
    outcome = stored_outcome(session, scan)
    # Review decisions can change finding flags after the original result was
    # recorded. Require a rescan rather than mix historical policy with new counts.
    if (outcome.total_findings, outcome.blocking_findings, outcome.suppressed_findings) != (
        scan.total_findings, scan.blocking_findings, scan.suppressed_findings
    ):
        raise SecretSentinelError(ErrorCode.INVALID_STATE, "Review decisions changed this scan. Rescan before exporting.")
    if format == "csv":
        content, media_type = to_csv(outcome), "text/csv"
    elif format == "sarif":
        content, media_type = to_sarif(outcome, repo.display_name), "application/sarif+json"
    else:
        content, media_type = to_json(outcome, repo.display_name), "application/json"
    return Response(content, media_type=media_type, headers={
        "Content-Disposition": f'attachment; filename="secretsentinel-{scan.id}.{format}"',
        "Cache-Control": "no-store",
    })


@router.post("/scans/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(scan_id: str, session: Session = Depends(get_db, scope="function"), jobs: ScanJobManager = Depends(get_jobs)):
    scan = get_or_404(session, Scan, scan_id)
    if scan.status not in ("queued", "running"):
        raise SecretSentinelError(ErrorCode.INVALID_STATE)
    jobs.cancel(scan.id)
    if scan.status == "queued":
        scan.status = "cancelled"
        scan.error_code = ErrorCode.SCAN_CANCELLED.value
        scan.policy_result = "not_evaluated"
    audit(session, "local-user", "scan.cancel_requested", "scan", scan.id)
    session.flush()
    return scan_out(session, scan)


@router.get("/scans/{scan_id}/findings", response_model=Page[FindingOut])
def scan_findings(
    scan_id: str,
    severity: str | None = Query(None, pattern="^(critical|high|medium|low)$"),
    status_: str | None = Query(None, alias="status", pattern="^(open|acknowledged|resolved|suppressed)$"),
    rule_id: str | None = Query(None, max_length=100),
    blocking: bool | None = None,
    pager: Pagination = Depends(),
    session: Session = Depends(get_db, scope="function"),
):
    scan = get_or_404(session, Scan, scan_id)
    repo = session.get(Repository, scan.repository_id)
    q = apply_finding_filters(select(Finding).where(Finding.scan_id == scan.id), severity, status_, rule_id, None, blocking)
    total = session.scalar(select(func.count()).select_from(q.subquery()))
    rows = session.scalars(q.order_by(Finding.blocking.desc(), SEVERITY_RANK, Finding.relative_path, Finding.start_line).offset(pager.offset).limit(pager.page_size)).all()
    items = [finding_out(f, scan.mode, repo.display_name if repo else "") for f in rows]
    return {"items": items, "total": total or 0, "page": pager.page, "page_size": pager.page_size}
