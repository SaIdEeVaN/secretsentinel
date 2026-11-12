"""Database engine/session management (SQLite by default)."""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, delete, event, func, select
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker

from .models import SCHEMA_VERSION, Attestation, Base, Meta, Scan

_lock = threading.Lock()
_engine: Engine | None = None
_session_factory: sessionmaker | None = None
_engine_url: str | None = None


def _prepare_sqlite_file(url: str) -> None:
    parsed = make_url(url)
    if parsed.get_backend_name() != "sqlite" or not parsed.database or parsed.database == ":memory:":
        return
    path = Path(parsed.database).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        # Create the file owner-read/write only before SQLite opens it.
        fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)


def normalize_db_url(url: str) -> str:
    """Accept provider-style Postgres URLs and use the psycopg 3 driver.

    Render, Supabase, Neon etc. hand out ``postgres://`` or ``postgresql://``
    connection strings; SQLAlchemy needs ``postgresql+psycopg://``.
    """
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://") :]
    return url


def redact_db_url(url: str) -> str:
    """Database URL safe to print (password hidden)."""
    try:
        return make_url(normalize_db_url(url)).render_as_string(hide_password=True)
    except Exception:  # noqa: BLE001 - never echo an unparsable URL that may hold a password
        return "<unparsable database URL>"


def init_engine(db_url: str) -> Engine:
    global _engine, _session_factory, _engine_url
    db_url = normalize_db_url(db_url)
    with _lock:
        if _engine is not None and _engine_url == db_url:
            return _engine
        if _engine is not None:
            _engine.dispose()
        _prepare_sqlite_file(db_url)
        kwargs: dict = {}
        if db_url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
        else:
            # Hosted databases drop idle connections; check before use.
            kwargs.update(pool_pre_ping=True, pool_recycle=300)
        engine = create_engine(db_url, **kwargs)
        if db_url.startswith("sqlite"):

            @event.listens_for(engine, "connect")
            def _sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - trivial
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA foreign_keys=ON")
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA secure_delete=ON")
                cur.close()

        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine, expire_on_commit=False)
        with factory() as session:
            meta = session.get(Meta, "schema_version")
            if meta is None:
                session.add(Meta(key="schema_version", value=str(SCHEMA_VERSION)))
                session.commit()
        _engine, _session_factory, _engine_url = engine, factory, db_url
        return engine


def reset_engine() -> None:
    global _engine, _session_factory, _engine_url
    with _lock:
        if _engine is not None:
            _engine.dispose()
        _engine = _session_factory = _engine_url = None


def get_session_factory() -> sessionmaker:
    if _session_factory is None:
        raise RuntimeError("database not initialised")
    return _session_factory


@contextmanager
def session_scope() -> Iterator[Session]:
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def mark_interrupted_scans(session: Session) -> int:
    """Scans left queued/running by a previous process can never complete."""
    stale = session.scalars(select(Scan).where(Scan.status.in_(("queued", "running")))).all()
    for scan in stale:
        scan.status = "failed"
        scan.policy_result = "not_evaluated"
        scan.error_code = "SCAN_INTERRUPTED"
        scan.finished_at = datetime.now(timezone.utc)
    return len(stale)


def prune_old_scans(session: Session, retention_days: int) -> int:
    """Delete scans older than ``retention_days`` (0 disables). Returns how many.

    Always kept, whatever their age:
    * each repository's most recent completed scan - the dashboard's current state;
    * scans still queued or running;
    * scans with an attestation - signed evidence must outlive the retention window.
    Findings of deleted scans are removed by the ON DELETE CASCADE foreign key.
    """
    if retention_days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    newest = (
        select(Scan.repository_id, func.max(Scan.created_at).label("newest"))
        .where(Scan.status == "completed")
        .group_by(Scan.repository_id)
        .subquery()
    )
    current = select(Scan.id).join(
        newest, (Scan.repository_id == newest.c.repository_id) & (Scan.created_at == newest.c.newest)
    ).where(Scan.status == "completed")
    ids = session.scalars(
        select(Scan.id).where(
            Scan.created_at < cutoff,
            Scan.status.notin_(("queued", "running")),
            Scan.id.notin_(current),
            Scan.id.notin_(select(Attestation.scan_id)),
        )
    ).all()
    for i in range(0, len(ids), 500):
        session.execute(delete(Scan).where(Scan.id.in_(ids[i : i + 500])).execution_options(synchronize_session=False))
    return len(ids)
