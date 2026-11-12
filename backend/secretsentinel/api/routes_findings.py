"""Findings: list/filter, detail with remediation, triage, suppressions."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from ..core.errors import ErrorCode, SecretSentinelError
from ..core.security import safe_text
from ..models import Finding, Repository, Scan, Suppression
from ..schemas import FindingDetail, FindingFacets, FindingOut, FindingUpdate, Page, SuppressionCreate, SuppressionOut
from ..services.policy import MAX_SUPPRESSION_DAYS
from ..services.remediation import get_remediation
from ..services.rules import load_ruleset
from ..services.types import SEVERITY_ORDER
from ..services.store import audit
from .deps import Pagination, finding_out, get_db, get_or_404

router = APIRouter(tags=["findings"])

SEVERITY_RANK = case(
    (Finding.severity == "critical", 0),
    (Finding.severity == "high", 1),
    (Finding.severity == "medium", 2),
    else_=3,
)


def apply_finding_filters(q, severity, status_, rule_id, mode, blocking):
    if severity:
        q = q.where(Finding.severity == severity)
    if status_:
        q = q.where(Finding.status == status_)
    if rule_id:
        q = q.where(Finding.rule_id == rule_id)
    if mode:
        q = q.where(Scan.mode == mode)
    if blocking is not None:
        q = q.where(Finding.blocking.is_(blocking))
    return q


def latest_completed_scan_ids(session: Session) -> list[str]:
    """Most recent completed scan per repository (for 'current' views/metrics)."""
    sub = (
        select(Scan.repository_id, func.max(Scan.created_at).label("latest"))
        .where(Scan.status == "completed")
        .group_by(Scan.repository_id)
        .subquery()
    )
    rows = session.execute(
        select(Scan.id).join(sub, (Scan.repository_id == sub.c.repository_id) & (Scan.created_at == sub.c.latest))
    ).all()
    return [r[0] for r in rows]


@router.get("/findings", response_model=Page[FindingOut])
def list_findings(
    severity: str | None = Query(None, pattern="^(critical|high|medium|low)$"),
    status_: str | None = Query(None, alias="status", pattern="^(open|acknowledged|resolved|suppressed)$"),
    rule_id: str | None = Query(None, max_length=100),
    mode: str | None = Query(None, pattern="^(dir|git|both|ci)$"),
    scan_id: str | None = Query(None, max_length=36),
    repository_id: str | None = Query(None, max_length=36),
    blocking: bool | None = None,
    latest_only: bool = Query(True, description="only findings from each repository's latest completed scan"),
    pager: Pagination = Depends(),
    session: Session = Depends(get_db, scope="function"),
):
    q = select(Finding, Scan.mode, Repository.display_name).join(Scan, Finding.scan_id == Scan.id).join(
        Repository, Finding.repository_id == Repository.id
    )
    if scan_id:
        q = q.where(Finding.scan_id == scan_id)
    elif latest_only:
        q = q.where(Finding.scan_id.in_(latest_completed_scan_ids(session) or [""]))
    if repository_id:
        q = q.where(Finding.repository_id == repository_id)
    q = apply_finding_filters(q, severity, status_, rule_id, mode, blocking)
    total = session.scalar(select(func.count()).select_from(q.subquery()))
    rows = session.execute(
        q.order_by(Finding.blocking.desc(), SEVERITY_RANK, Finding.relative_path, Finding.start_line)
        .offset(pager.offset)
        .limit(pager.page_size)
    ).all()
    items = [finding_out(f, m, name) for f, m, name in rows]
    return {"items": items, "total": total or 0, "page": pager.page, "page_size": pager.page_size}


SEVERITIES = ("critical", "high", "medium", "low")
STATUSES = ("open", "acknowledged", "resolved", "suppressed")


@router.get("/findings/facets", response_model=FindingFacets)
def finding_facets(
    severity: str | None = Query(None, pattern="^(critical|high|medium|low)$"),
    status_: str | None = Query(None, alias="status", pattern="^(open|acknowledged|resolved|suppressed)$"),
    rule_id: str | None = Query(None, max_length=100),
    mode: str | None = Query(None, pattern="^(dir|git|both|ci)$"),
    scan_id: str | None = Query(None, max_length=36),
    repository_id: str | None = Query(None, max_length=36),
    blocking: bool | None = None,
    latest_only: bool = Query(True),
    session: Session = Depends(get_db, scope="function"),
):
    """Counts by severity and by status for the same scope as ``GET /findings``.

    Declared before ``/findings/{finding_id}`` so "facets" is never read as an id.
    """
    latest = None if scan_id or not latest_only else (latest_completed_scan_ids(session) or [""])

    def scoped():
        q = select(Finding.severity, Finding.status).join(Scan, Finding.scan_id == Scan.id).join(
            Repository, Finding.repository_id == Repository.id
        )
        if scan_id:
            q = q.where(Finding.scan_id == scan_id)
        elif latest is not None:
            q = q.where(Finding.scan_id.in_(latest))
        if repository_id:
            q = q.where(Finding.repository_id == repository_id)
        return q

    def grouped(q, column: str, keys: tuple[str, ...]) -> dict[str, int]:
        sub = q.subquery()
        rows = session.execute(select(sub.c[column], func.count()).group_by(sub.c[column])).all()
        counts = {k: 0 for k in keys}
        counts.update({k: n for k, n in rows if k in counts})
        return counts

    everything = apply_finding_filters(scoped(), severity, status_, rule_id, mode, blocking)
    return FindingFacets(
        total=session.scalar(select(func.count()).select_from(everything.subquery())) or 0,
        severity=grouped(apply_finding_filters(scoped(), None, status_, rule_id, mode, blocking), "severity", SEVERITIES),
        status=grouped(apply_finding_filters(scoped(), severity, None, rule_id, mode, blocking), "status", STATUSES),
    )


def _detail(session: Session, f: Finding) -> dict:
    scan = session.get(Scan, f.scan_id)
    repo = session.get(Repository, f.repository_id)
    latest = session.scalars(
        select(Scan)
        .where(Scan.repository_id == f.repository_id, Scan.status == "completed")
        .order_by(Scan.created_at.desc())
        .limit(1)
    ).first()
    still = False
    if latest is not None:
        still = (
            session.scalar(
                select(Finding.id).where(Finding.scan_id == latest.id, Finding.fingerprint == f.fingerprint).limit(1)
            )
            is not None
        )
    occurrences = session.scalar(
        select(func.count()).where(Finding.repository_id == f.repository_id, Finding.fingerprint == f.fingerprint)
    )
    description = None
    try:
        description = load_ruleset().meta(f.rule_id).description
    except SecretSentinelError:
        pass
    base = finding_out(f, scan.mode if scan else "", repo.display_name if repo else "")
    return FindingDetail(
        **base,
        remediation=get_remediation(f.remediation_key).as_dict(),
        rule_description=description,
        still_detected=still,
        latest_scan_id=latest.id if latest else None,
        occurrences=occurrences or 0,
    ).model_dump()


@router.get("/findings/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: str, session: Session = Depends(get_db, scope="function")):
    return _detail(session, get_or_404(session, Finding, finding_id))


@router.patch("/findings/{finding_id}", response_model=FindingDetail)
def update_finding(finding_id: str, body: FindingUpdate, session: Session = Depends(get_db, scope="function")):
    f = get_or_404(session, Finding, finding_id)
    if f.status == "suppressed":
        raise SecretSentinelError(ErrorCode.INVALID_STATE, "Deactivate the suppression first.")
    previous = f.status
    f.status = body.status
    f.status_updated_at = datetime.now(timezone.utc)
    audit(session, "local-user", "finding.status_changed", "finding", f.id, previous=previous, new=body.status)
    session.flush()
    return _detail(session, f)


# --- suppressions -----------------------------------------------------------

def _suppression_out(s: Suppression) -> SuppressionOut:
    today = datetime.now(timezone.utc).date()
    return SuppressionOut(
        id=s.id,
        repository_id=s.repository_id,
        rule_id=s.rule_id,
        fingerprint=s.fingerprint,
        path=s.path,
        line=s.line,
        commit_sha=s.commit_sha,
        reason=s.reason,
        reviewer=s.reviewer,
        created_at=s.created_at if s.created_at.tzinfo else s.created_at.replace(tzinfo=timezone.utc),
        expires_at=s.expires_at,
        active=s.active,
        expired=s.expires_at < today,
    )


@router.get("/suppressions", response_model=list[SuppressionOut])
def list_suppressions(repository_id: str | None = Query(None, max_length=36), session: Session = Depends(get_db, scope="function")):
    q = select(Suppression).order_by(Suppression.created_at.desc())
    if repository_id:
        q = q.where(Suppression.repository_id == repository_id)
    return [_suppression_out(s) for s in session.scalars(q).all()]


@router.post("/suppressions", response_model=SuppressionOut, status_code=status.HTTP_201_CREATED)
def create_suppression(body: SuppressionCreate, session: Session = Depends(get_db, scope="function")):
    f = get_or_404(session, Finding, body.finding_id)
    today = datetime.now(timezone.utc).date()
    if body.expires_at < today or body.expires_at > today + timedelta(days=MAX_SUPPRESSION_DAYS):
        raise SecretSentinelError(ErrorCode.VALIDATION_ERROR, f"Expiry must be within {MAX_SUPPRESSION_DAYS} days.")
    s = Suppression(
        repository_id=f.repository_id,
        rule_id=f.rule_id,
        fingerprint=None,
        path=f.relative_path,
        line=f.start_line,
        commit_sha=f.commit_sha,
        reason=safe_text(body.reason, 500),
        reviewer=safe_text(body.reviewer, 120),
        expires_at=body.expires_at,
        active=True,
    )
    session.add(s)
    session.flush()
    # The suppression applies to FUTURE scans; the current record is marked
    # so the dashboard reflects the reviewed decision immediately.
    previous = f.status
    f.status = "suppressed"
    f.suppression_id = f"db-{s.id[:8]}"
    f.blocking = False
    f.status_updated_at = datetime.now(timezone.utc)
    audit(
        session, safe_text(body.reviewer, 120), "suppression.created", "suppression", s.id,
        finding_id=f.id, rule_id=f.rule_id, expires_at=body.expires_at.isoformat(), previous=previous,
    )
    return _suppression_out(s)


@router.delete("/suppressions/{suppression_id}", response_model=SuppressionOut)
def deactivate_suppression(suppression_id: str, session: Session = Depends(get_db, scope="function")):
    s = get_or_404(session, Suppression, suppression_id)
    s.active = False
    tag = f"db-{s.id[:8]}"
    for f in session.scalars(select(Finding).where(Finding.suppression_id == tag)).all():
        f.status = "open"
        f.suppression_id = None
        scan = session.get(Scan, f.scan_id)
        threshold = scan.fail_on if scan else "high"
        f.blocking = threshold != "none" and SEVERITY_ORDER.get(f.severity, 0) >= SEVERITY_ORDER.get(threshold, 3)
        f.status_updated_at = datetime.now(timezone.utc)
    audit(session, "local-user", "suppression.deactivated", "suppression", s.id)
    session.flush()
    return _suppression_out(s)


_ = date  # re-exported type used in annotations above
