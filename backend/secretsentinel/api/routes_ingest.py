"""P1: authenticated ingestion of SANITIZED scan summaries from a trusted workflow.

Disabled unless INGEST_TOKEN is configured. The body must match the strict
``secretsentinel-report/v1`` schema (unknown fields rejected), so a raw
Gitleaks report - which has Secret/Match fields - cannot be ingested. Never
give this token to pull-request jobs (PRD CI constraints).
"""

from __future__ import annotations

import hmac
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from ..core.config import Settings
from ..core.errors import ErrorCode, SecretSentinelError
from ..core.security import safe_text
from ..models import Repository
from ..schemas import IngestReport, ScanCreated
from ..services.store import record_outcome
from ..services.types import SafeFinding, ScanOutcome
from .deps import get_db, get_settings

router = APIRouter(tags=["ingest"])


def require_ingest_token(request: Request, settings: Settings = Depends(get_settings)) -> None:
    if not settings.ingest_token:
        raise SecretSentinelError(ErrorCode.FEATURE_DISABLED)
    header = request.headers.get("authorization", "")
    supplied = header[7:] if header.lower().startswith("bearer ") else ""
    if not supplied or not hmac.compare_digest(supplied.encode(), settings.ingest_token.encode()):
        raise SecretSentinelError(ErrorCode.UNAUTHORIZED)


@router.post(
    "/ingest/scan-summary",
    response_model=ScanCreated,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_ingest_token)],
)
def ingest(body: IngestReport, session: Session = Depends(get_db)):
    name = safe_text(body.repository_name or body.scan.target or "ci-repository", 200)
    key = f"ci:{name}"
    repo = session.query(Repository).filter(Repository.canonical_local_path == key).one_or_none()
    if repo is None:
        repo = Repository(display_name=name, canonical_local_path=key)
        session.add(repo)
        session.flush()
    s = body.scan
    outcome = ScanOutcome(
        mode=s.mode,
        status=s.status,
        error_code=s.error_code if s.status != "completed" else None,
        policy_result=s.policy_result if s.status == "completed" else "not_evaluated",
        fail_on=s.fail_on,
        scanner_version=body.tool.scanner_version,
        secretsentinel_version=body.tool.version,
        ruleset_version=body.tool.ruleset_version,
        ruleset_digest=body.tool.ruleset_digest,
        policy_digest=body.tool.policy_digest,
        commit_sha=s.commit_sha,
        scope=safe_text(s.scope, 128),
        started_at=s.started_at or datetime.now(timezone.utc),
        finished_at=s.finished_at or datetime.now(timezone.utc),
        warnings=[safe_text(w, 200) for w in s.warnings],
    )
    if s.error_code is not None:
        try:
            ErrorCode(s.error_code)
        except ValueError:
            outcome.error_code = ErrorCode.INTERNAL_ERROR.value
    for f in body.findings:
        outcome.findings.append(
            SafeFinding(
                rule_id=f.rule_id,
                relative_path=safe_text(f.relative_path, 1024),
                start_line=f.start_line,
                end_line=f.end_line,
                start_column=f.start_column,
                commit_sha=f.commit_sha,
                entropy=f.entropy,
                sources=tuple(f.sources),
                also_matched=tuple(a for a in f.also_matched if len(a) <= 100),
                title=safe_text(f.title, 200),
                severity=f.severity,
                confidence=f.confidence,
                family=safe_text(f.rule_family, 64),
                remediation_key=f.remediation_key,
                requirement=f.requirement,
                status=f.status,
                suppression_id=f.suppression_id,
                blocking=f.blocking,
            )
        )
    scan = record_outcome(session, repo, outcome, "ingest")
    scan.mode = "ci"
    return ScanCreated(scan_id=scan.id, status=scan.status)
