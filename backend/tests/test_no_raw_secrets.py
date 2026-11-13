"""End-to-end secret-canary tests (PRD 4.3 "Safe reporting", S1/S2, CI-05).

Every synthetic fixture value is a canary. After scanning the full fixture
set with the REAL Gitleaks engine through every interface, none of the
canaries (nor distinctive prefixes/suffixes) may appear in:
CLI stdout/stderr, JSON/SARIF/CSV exports, GitHub annotations/summary,
API responses, the SQLite database (full dump) or application logs.
"""

import json
import logging
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from secretsentinel.cli import main
from secretsentinel.core.config import Settings
from secretsentinel.fixtures import find_leaks
from secretsentinel.main import create_app

pytestmark = pytest.mark.gitleaks


def _assert_clean(text: str, canaries: set[str], where: str) -> None:
    leaks = find_leaks(text, canaries)
    assert not leaks, f"canary leaked into {where}: {leaks}"


def test_cli_outputs_contain_no_canaries(gitleaks_bin, fixture_root, canaries, tmp_path, capfd, monkeypatch):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("DB_URL", f"sqlite:///{(tmp_path / 'cli.db').as_posix()}")
    outputs = []
    for fmt in ("text", "json", "sarif", "csv"):
        out = tmp_path / f"report.{fmt}"
        rc = main(["scan", "dir", str(fixture_root), "--format", fmt, "--output", str(out), "--gitleaks", gitleaks_bin,
                   "--github-annotations", "--github-summary", "--verbose"])
        assert rc == 1
        outputs.append(out.read_text())
    captured = capfd.readouterr()
    _assert_clean(captured.out + captured.err, canaries, "CLI stdout/stderr")
    for text in outputs:
        _assert_clean(text, canaries, "exported report")
    _assert_clean(summary.read_text(), canaries, "GitHub step summary")
    dump = "\n".join(sqlite3.connect(tmp_path / "cli.db").iterdump())
    _assert_clean(dump, canaries, "SQLite dump")
    assert "INSERT INTO" in dump and "findings" in dump  # the dump really contains data


def test_api_and_db_contain_no_canaries(gitleaks_bin, fixture_root, canaries, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    root = fixture_root.parent
    db = tmp_path / "api.db"
    settings = Settings(gitleaks_path=gitleaks_bin, db_url=f"sqlite:///{db.as_posix()}", scan_root_allowlist=(root,))
    with TestClient(create_app(settings), base_url="http://127.0.0.1:8000") as c:
        repo = c.post("/api/v1/repositories", json={"path": str(fixture_root)}).json()
        sid = c.post("/api/v1/scans", json={"repository_id": repo["id"], "mode": "dir"}).json()["scan_id"]
        for _ in range(300):
            scan = c.get(f"/api/v1/scans/{sid}").json()
            if scan["status"] not in ("queued", "running"):
                break
            time.sleep(0.1)
        assert scan["status"] == "completed" and scan["total_findings"] >= 25
        bodies = [json.dumps(scan)]
        findings = c.get("/api/v1/findings", params={"page_size": 200}).json()
        bodies.append(json.dumps(findings))
        for f in findings["items"]:
            bodies.append(c.get(f"/api/v1/findings/{f['id']}").text)
        for url in ("/api/v1/metrics/overview", f"/api/v1/scans/{sid}/findings?page_size=200", "/api/v1/audit-events",
                    "/api/v1/repositories", "/api/v1/scans"):
            bodies.append(c.get(url).text)
    _assert_clean("\n".join(bodies), canaries, "API responses")
    _assert_clean("\n".join(sqlite3.connect(db).iterdump()), canaries, "SQLite dump")
    _assert_clean("\n".join(r.getMessage() + str(getattr(r, "ss", "")) for r in caplog.records), canaries, "logs")


def test_repeated_character_runs_are_not_canary_fragments():
    """The synthetic Twitter token starts with 21 "A"s; 20 "A"s on their own must not look like a leak."""
    from secretsentinel.fixtures import canary_fragments, find_leaks, synth

    value = synth("twitter_bearer21", "fragment-test")
    fragments = canary_fragments({value})
    assert value in fragments and value[-20:] in fragments
    assert value[:20] not in fragments
    assert find_leaks("x" * 5 + "A" * 40, {value}) == []
    assert find_leaks(f"log {value} end", {value})  # the whole value is still caught
