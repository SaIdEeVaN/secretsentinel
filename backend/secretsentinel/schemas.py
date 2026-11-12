"""Pydantic API contracts.

Response models list every field explicitly; FastAPI filters responses through
them, so even a programming mistake that attached extra data to an ORM object
could not reach the browser. Request models forbid unknown fields.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

T = TypeVar("T")

Severity = Literal["critical", "high", "medium", "low"]
FailOn = Literal["critical", "high", "medium", "low", "none"]
Mode = Literal["dir", "git", "both"]
TriageStatus = Literal["open", "acknowledged", "resolved"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _no_control_chars(value: str) -> str:
    if any(ord(c) < 32 or 127 <= ord(c) < 160 for c in value):
        raise ValueError("control characters are not allowed")
    return value


class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorBody


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


# --- repositories -----------------------------------------------------------
class RepositoryCreate(StrictModel):
    path: str = Field(min_length=1, max_length=4096)
    display_name: str | None = Field(default=None, max_length=200)

    _v_path = field_validator("path")(_no_control_chars)


class RepositoryOut(BaseModel):
    id: str
    display_name: str
    local_path: str
    allowed: bool
    created_at: datetime
    last_scan_id: str | None = None
    last_scan_status: str | None = None
    last_policy_result: str | None = None
    last_scan_at: datetime | None = None


# --- scans ------------------------------------------------------------------
class ScanCreate(StrictModel):
    repository_id: str = Field(min_length=36, max_length=36)
    mode: Mode = "both"
    since_ref: str | None = Field(default=None, max_length=200)
    fail_on: FailOn | None = None


class ScanCreated(BaseModel):
    scan_id: str
    status: str


class ScanOut(BaseModel):
    id: str
    repository_id: str
    repository_name: str
    source: str
    mode: str
    status: str
    policy_result: str
    fail_on: str
    since_ref: str | None
    scope: str | None
    commit_sha: str | None
    scanner_name: str
    scanner_version: str | None
    secretsentinel_version: str | None
    ruleset_version: str | None
    ruleset_digest: str | None
    policy_digest: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    duration_ms: int | None
    total_findings: int
    blocking_findings: int
    suppressed_findings: int
    severity_counts: dict[str, int]
    error_code: str | None
    error_message: str | None
    warnings: list[str]


# --- findings ---------------------------------------------------------------
class FindingOut(BaseModel):
    id: str
    scan_id: str
    scan_mode: str
    repository_id: str
    repository_name: str
    fingerprint: str
    rule_id: str
    rule_family: str
    title: str
    severity: str
    confidence: str
    requirement: str | None
    relative_path: str
    start_line: int
    end_line: int
    commit_sha: str | None
    sources: list[str]
    also_matched: list[str]
    status: str
    suppression_id: str | None
    blocking: bool
    remediation_key: str
    first_seen_at: datetime
    last_seen_at: datetime
    status_updated_at: datetime | None


class RemediationOut(BaseModel):
    key: str
    title: str
    risk: str
    urgency: str
    steps: list[str]
    notes: list[str]


class FindingFacets(BaseModel):
    """Counts for the Findings filter chips. Each dimension ignores its own filter."""

    total: int
    severity: dict[str, int]
    status: dict[str, int]


class FindingDetail(FindingOut):
    remediation: RemediationOut
    rule_description: str | None
    still_detected: bool
    latest_scan_id: str | None
    occurrences: int


class FindingUpdate(StrictModel):
    status: TriageStatus


# --- suppressions -----------------------------------------------------------
class SuppressionCreate(StrictModel):
    finding_id: str = Field(min_length=36, max_length=36)
    reason: str = Field(min_length=10, max_length=500)
    reviewer: str = Field(min_length=1, max_length=120)
    expires_at: date

    _v_reason = field_validator("reason")(_no_control_chars)
    _v_reviewer = field_validator("reviewer")(_no_control_chars)


class SuppressionOut(BaseModel):
    id: str
    repository_id: str
    rule_id: str
    fingerprint: str | None
    path: str | None
    line: int | None
    commit_sha: str | None
    reason: str
    reviewer: str
    created_at: datetime
    expires_at: date
    active: bool
    expired: bool


# --- metrics / system -------------------------------------------------------
class TrendPoint(BaseModel):
    scan_id: str
    created_at: datetime
    repository_name: str
    mode: str
    status: str
    policy_result: str
    total_findings: int
    blocking_findings: int


class MetricsOverview(BaseModel):
    repositories: int
    scans_total: int
    scans_completed: int
    scans_failed: int
    open_findings: int
    blocking_open_findings: int
    severity_counts: dict[str, int]
    family_counts: dict[str, int]
    latest_scans: list[ScanOut]
    trend: list[TrendPoint]


class RuleOut(BaseModel):
    rule_id: str
    title: str
    severity: str
    confidence: str
    family: str
    remediation_key: str
    requirement: str | None
    description: str | None
    web3: bool
    mapping_source: str


class RulesResponse(BaseModel):
    ruleset_version: str
    ruleset_digest: str
    default_severity: str
    rules: list[RuleOut]
    low_confidence_paths: list[str]


class ScannerStatus(BaseModel):
    available: bool
    version: str | None
    error_code: str | None
    message: str | None


class SystemStatus(BaseModel):
    version: str
    app_env: str
    scanner: ScannerStatus
    git_available: bool
    ruleset_version: str | None
    ruleset_digest: str | None
    allowed_roots: list[str]
    default_fail_on: str
    timeout_seconds: int
    max_file_mb: int
    max_concurrent_scans: int
    auth_required: bool
    blockchain_enabled: bool
    local_scanning_enabled: bool
    ingest_enabled: bool
    hosted: bool


class AuditEventOut(BaseModel):
    id: str
    actor: str
    action: str
    entity_type: str
    entity_id: str
    occurred_at: datetime
    metadata: dict


class DemoCreated(BaseModel):
    repository: RepositoryOut


# --- P1: trusted ingestion of sanitized CI summaries -----------------------
class IngestTool(StrictModel):
    name: Literal["SecretSentinel"]
    version: str = Field(max_length=32)
    scanner: str = Field(max_length=32)
    scanner_version: str | None = Field(default=None, max_length=32)
    ruleset_version: str | None = Field(default=None, max_length=32)
    ruleset_digest: str | None = Field(default=None, max_length=80)
    policy_digest: str | None = Field(default=None, max_length=80)


class IngestScan(StrictModel):
    target: str = Field(max_length=200)
    mode: Mode
    scope: str = Field(default="", max_length=128)
    status: Literal["completed", "failed", "cancelled"]
    error_code: str | None = Field(default=None, max_length=40)
    error_message: str | None = Field(default=None, max_length=300)
    policy_result: Literal["pass", "fail", "not_evaluated"]
    fail_on: FailOn
    commit_sha: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}([0-9a-f]{24})?$")
    started_at: datetime | None = None
    finished_at: datetime | None = None
    total_findings: int = Field(ge=0)
    blocking_findings: int = Field(ge=0)
    suppressed_findings: int = Field(ge=0)
    severity_counts: dict[Severity, int]
    warnings: list[str] = Field(default_factory=list, max_length=50)
    id: str | None = Field(default=None, max_length=36)


class IngestFinding(StrictModel):
    fingerprint: str = Field(pattern=r"^ss1:[0-9a-f]{32}$")
    rule_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,99}$")
    title: str = Field(max_length=200)
    rule_family: str = Field(max_length=64)
    severity: Severity
    confidence: Literal["high", "medium", "low"]
    requirement: str | None = Field(default=None, max_length=16)
    relative_path: str = Field(max_length=1024)
    start_line: int = Field(ge=0)
    end_line: int = Field(ge=0)
    start_column: int = Field(default=0, ge=0)
    commit_sha: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}([0-9a-f]{24})?$")
    entropy: float | None = Field(default=None, ge=0, le=64)
    sources: list[Literal["dir", "git"]] = Field(default_factory=list)
    also_matched: list[str] = Field(default_factory=list, max_length=20)
    status: Literal["open", "suppressed"]
    suppression_id: str | None = Field(default=None, max_length=64)
    blocking: bool
    remediation_key: str = Field(max_length=48)

    _v_path = field_validator("relative_path", "title")(_no_control_chars)


class IngestReport(StrictModel):
    schema_: Literal["secretsentinel-report/v1"] = Field(alias="schema")
    tool: IngestTool
    scan: IngestScan
    findings: list[IngestFinding] = Field(max_length=10_000)
    repository_name: str | None = Field(default=None, max_length=200)

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


# --- P2: attestations -------------------------------------------------------
class AttestationOut(BaseModel):
    scan_id: str
    payload: dict
    canonical_payload: str
    attestation_digest: str
    signature: str
    signer_address: str
    chain_id: int | None
    contract_address: str | None
    transaction_hash: str | None
    published_at: datetime | None


class AttestationVerifyRequest(StrictModel):
    payload: dict
    signature: str = Field(max_length=140)
    signer_address: str = Field(max_length=42)
    check_onchain: bool = False


class VerificationCheck(BaseModel):
    name: str
    ok: bool
    detail: str


class AttestationVerifyResult(BaseModel):
    verified: bool
    label: str
    attestation_digest: str | None
    recovered_signer: str | None
    checks: list[VerificationCheck]
    disclaimer: str
