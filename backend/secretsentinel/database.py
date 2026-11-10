"""Database engine/session management (SQLite by default)."""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, event, select
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker

from .models import SCHEMA_VERSION, Base, Meta, Scan

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


def init_engine(db_url: str) -> Engine:
    global _engine, _session_factory, _engine_url
    with _lock:
        if _engine is not None and _engine_url == db_url:
            return _engine
        if _engine is not None:
            _engine.dispose()
        _prepare_sqlite_file(db_url)
        kwargs: dict = {}
        if db_url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
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
    if retention_days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    old = session.scalars(select(Scan).where(Scan.created_at < cutoff)).all()
    for scan in old:
        session.delete(scan)
    return len(old)
