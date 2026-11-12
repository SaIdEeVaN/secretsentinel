"""Scan history retention never removes current state or signed evidence."""

import os
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from secretsentinel.database import init_engine, prune_old_scans, reset_engine, session_scope
from secretsentinel.models import Attestation, Finding, Repository, Scan

NOW = datetime.now(timezone.utc)


@pytest.fixture
def db(tmp_path):
    # Set SECRETSENTINEL_TEST_DATABASE_URL to run against Postgres (the hosted database);
    # the schema is dropped first so every test starts empty.
    url = os.environ.get("SECRETSENTINEL_TEST_DATABASE_URL")
    reset_engine()
    if url:
        from sqlalchemy import create_engine

        from secretsentinel.database import normalize_db_url
        from secretsentinel.models import Base

        engine = create_engine(normalize_db_url(url))
        Base.metadata.drop_all(engine)
        engine.dispose()
    init_engine(url or f"sqlite:///{(tmp_path / 'retention.db').as_posix()}")
    yield
    reset_engine()


def _scan(s, repo, days_old, status="completed", findings=0):
    scan = Scan(repository_id=repo.id, mode="ci", status=status, created_at=NOW - timedelta(days=days_old))
    s.add(scan)
    s.flush()
    for i in range(findings):
        s.add(Finding(scan_id=scan.id, repository_id=repo.id, fingerprint=f"ss1:{scan.id[:8]}{i:024d}", rule_id="r",
                      rule_family="f", title="t", severity="low", confidence="low", relative_path="a", remediation_key="k"))
    return scan.id


def test_prune_keeps_current_state_running_scans_and_attested_scans(db):
    with session_scope() as s:
        a = Repository(display_name="a", canonical_local_path="ci:a")
        b = Repository(display_name="b", canonical_local_path="ci:b")
        s.add_all([a, b])
        s.flush()
        ids = {
            "a_old": _scan(s, a, 400, findings=3),           # superseded by a newer scan -> pruned
            "a_old_failed": _scan(s, a, 390, "failed"),      # old failure -> pruned
            "a_current": _scan(s, a, 1, findings=1),         # recent -> kept
            "b_current_but_old": _scan(s, b, 500),           # b's only completed scan -> kept
            "b_attested": _scan(s, b, 600),                  # signed evidence -> kept
            "b_stuck_running": _scan(s, b, 700, "running"),  # not finished -> kept
        }
        s.add(Attestation(scan_id=ids["b_attested"], payload_json="{}", attestation_digest="0x" + "0" * 64,
                          signature="0x00", signer_address="0x" + "0" * 40))

    with session_scope() as s:
        assert prune_old_scans(s, 180) == 2

    with session_scope() as s:
        left = set(s.scalars(select(Scan.id)))
        assert left == {ids["a_current"], ids["b_current_but_old"], ids["b_attested"], ids["b_stuck_running"]}
        # findings of pruned scans went with them; the current scan's finding stayed
        assert s.scalar(select(func.count()).select_from(Finding)) == 1
        assert s.scalar(select(func.count()).select_from(Attestation)) == 1


def test_zero_disables_pruning(db):
    with session_scope() as s:
        r = Repository(display_name="r", canonical_local_path="ci:r")
        s.add(r)
        s.flush()
        _scan(s, r, 900)
        _scan(s, r, 800)
    with session_scope() as s:
        assert prune_old_scans(s, 0) == 0
        assert s.scalar(select(func.count()).select_from(Scan)) == 2
