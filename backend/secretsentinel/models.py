"""SQLite ORM models (PRD section 10).

There is deliberately NO column for a secret, a match, a source line, a raw
report or unfiltered error text. ``error_code`` is a controlled enum value.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

SCHEMA_VERSION = 1


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Meta(Base):
    __tablename__ = "meta"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(256))


class Repository(Base):
    __tablename__ = "repositories"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    display_name: Mapped[str] = mapped_column(String(200))
    # Local database only: never exported, published, or put on-chain.
    canonical_local_path: Mapped[str] = mapped_column(String(4096), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    scans: Mapped[list["Scan"]] = relationship(back_populates="repository", cascade="all, delete-orphan", passive_deletes=True)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(16), default="api")  # api | cli | ingest
    mode: Mapped[str] = mapped_column(String(8))  # dir | git | both | ci
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    policy_result: Mapped[str] = mapped_column(String(16), default="not_evaluated")
    fail_on: Mapped[str | None] = mapped_column(String(16), nullable=True)
    since_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    scope: Mapped[str | None] = mapped_column(String(128), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    scanner_name: Mapped[str] = mapped_column(String(32), default="gitleaks")
    scanner_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    secretsentinel_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ruleset_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ruleset_digest: Mapped[str | None] = mapped_column(String(80), nullable=True)
    policy_digest: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    blocking_findings: Mapped[int] = mapped_column(Integer, default=0)
    suppressed_findings: Mapped[int] = mapped_column(Integer, default=0)
    error_code: Mapped[str | None] = mapped_column(String(40), nullable=True)
    warnings_json: Mapped[str] = mapped_column(Text, default="[]")
    repository: Mapped[Repository] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(40), index=True)
    rule_id: Mapped[str] = mapped_column(String(100), index=True)
    rule_family: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(16))
    requirement: Mapped[str | None] = mapped_column(String(16), nullable=True)
    relative_path: Mapped[str] = mapped_column(String(1024))
    start_line: Mapped[int] = mapped_column(Integer, default=0)
    end_line: Mapped[int] = mapped_column(Integer, default=0)
    start_column: Mapped[int] = mapped_column(Integer, default=0)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entropy: Mapped[float | None] = mapped_column(Float, nullable=True)
    sources: Mapped[str] = mapped_column(String(32), default="")
    also_matched: Mapped[str] = mapped_column(String(512), default="")
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    suppression_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    blocking: Mapped[bool] = mapped_column(Boolean, default=False)
    remediation_key: Mapped[str] = mapped_column(String(48))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    status_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scan: Mapped[Scan] = relationship(back_populates="findings")

    __table_args__ = (Index("ix_findings_repo_fingerprint", "repository_id", "fingerprint"),)


class Suppression(Base):
    __tablename__ = "suppressions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(100))
    fingerprint: Mapped[str | None] = mapped_column(String(40), nullable=True)
    path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reason: Mapped[str] = mapped_column(String(500))
    reviewer: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[date] = mapped_column(Date)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(64), index=True)
    entity_type: Mapped[str] = mapped_column(String(32))
    entity_id: Mapped[str] = mapped_column(String(64), index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    safe_metadata_json: Mapped[str] = mapped_column(Text, default="{}")


class Attestation(Base):
    """P2: signed, non-sensitive scan attestation (optionally anchored on Sepolia)."""

    __tablename__ = "attestations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), unique=True)
    payload_json: Mapped[str] = mapped_column(Text)
    attestation_digest: Mapped[str] = mapped_column(String(66))
    signature: Mapped[str] = mapped_column(String(140))
    signer_address: Mapped[str] = mapped_column(String(42))
    chain_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    contract_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    transaction_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
