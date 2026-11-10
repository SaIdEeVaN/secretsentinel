"""CLI exit codes, outputs and the dependency-light CI path."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from secretsentinel.cli import EXIT_BLOCKING, EXIT_PASS, EXIT_SCAN_ERROR, EXIT_USAGE, main
from secretsentinel.services.exporters import github_annotations
from secretsentinel.services.types import SafeFinding, ScanOutcome

from .conftest import raw_record

BACKEND = Path(__file__).resolve().parents[1]


def test_exit_pass_on_clean(fake_gitleaks, tmp_path, capsys):
    fake_gitleaks.scenario("clean")
    rc = main(["check", str(tmp_path), "--mode", "dir", "--gitleaks", fake_gitleaks.path])
    out = capsys.readouterr().out
    assert rc == EXIT_PASS
    assert "No matching secrets detected in the scanned scope." in out
    assert "100% secure" not in out  # FIND-05: never overclaim


def test_exit_blocking(fake_gitleaks, tmp_path, capsys):
    fake_gitleaks.records([raw_record("f" * 8 + "0123456789abcdef" * 3 + "01234567")])
    rc = main(["check", str(tmp_path), "--mode", "dir", "--gitleaks", fake_gitleaks.path])
    assert rc == EXIT_BLOCKING
    assert "BLOCKING" in capsys.readouterr().out


def test_fail_on_critical_lets_high_pass(fake_gitleaks, tmp_path):
    fake_gitleaks.records([raw_record("x" * 40, RuleID="github-pat")])
    assert main(["check", str(tmp_path), "--mode", "dir", "--fail-on", "critical", "--gitleaks", fake_gitleaks.path]) == EXIT_PASS
    assert main(["check", str(tmp_path), "--mode", "dir", "--fail-on", "high", "--gitleaks", fake_gitleaks.path]) == EXIT_BLOCKING


@pytest.mark.parametrize("scenario", ["crash", "bad-json", "no-report", "timeout"])
def test_exit_scan_error_fails_closed(fake_gitleaks, tmp_path, scenario):
    fake_gitleaks.scenario(scenario)
    rc = main(["check", str(tmp_path), "--mode", "dir", "--timeout", "1", "--gitleaks", fake_gitleaks.path])
    assert rc == EXIT_SCAN_ERROR


def test_missing_scanner_exit_code(tmp_path):
    assert main(["check", str(tmp_path), "--gitleaks", "/no/such/gitleaks"]) == EXIT_SCAN_ERROR


def test_usage_errors(tmp_path, capsys):
    assert main(["check", str(tmp_path / "missing")]) == EXIT_USAGE
    (tmp_path / ".secretsentinel.yml").write_text("fail_on: nope\n")
    assert main(["check", str(tmp_path)]) == EXIT_USAGE
    with pytest.raises(SystemExit) as e:
        main(["check"])
    assert e.value.code == EXIT_USAGE


def test_json_sarif_csv_outputs(fake_gitleaks, tmp_path):
    fake_gitleaks.records([raw_record("deadbeef" * 8)])
    out = tmp_path / "out"
    for fmt in ("json", "sarif", "csv"):
        rc = main(["check", str(tmp_path), "--mode", "dir", "--format", fmt, "--output", str(out / f"r.{fmt}"),
                   "--gitleaks", fake_gitleaks.path])
        assert rc == EXIT_BLOCKING
    report = json.loads((out / "r.json").read_text())
    assert report["schema"] == "secretsentinel-report/v1"
    assert report["scan"]["blocking_findings"] == 1
    assert str(tmp_path) not in (out / "r.json").read_text()  # no absolute local paths in exports
    sarif = json.loads((out / "r.sarif").read_text())
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"][0]["level"] == "error"
    assert "deadbeef" * 8 not in "".join(p.read_text() for p in out.iterdir())


def test_github_annotation_escaping():
    evil = "a%b\n::set-output name=x::y,c:d.js"
    o = ScanOutcome(mode="dir", status="completed", findings=[
        SafeFinding(rule_id="github-pat", relative_path=evil, start_line=2, end_line=2, title="T", blocking=True)])
    lines = list(github_annotations(o))
    assert len(lines) == 1 and "\n" not in lines[0]
    assert "file=a%25b%0A%3A%3Aset-output name=x%3A%3Ay%2Cc%3Ad.js" in lines[0]


def test_github_summary_written(fake_gitleaks, tmp_path, monkeypatch):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    fake_gitleaks.records([raw_record("cafebabe" * 8)])
    main(["check", str(tmp_path), "--mode", "dir", "--github-summary", "--gitleaks", fake_gitleaks.path])
    text = summary.read_text()
    assert "SecretSentinel security scan" in text and "cafebabe" not in text


def test_scan_stores_results_in_db(fake_gitleaks, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("DB_URL", f"sqlite:///{(tmp_path / 'cli.db').as_posix()}")
    fake_gitleaks.records([raw_record("0badc0de" * 8)])
    rc = main(["scan", "dir", str(tmp_path), "--gitleaks", fake_gitleaks.path])
    assert rc == EXIT_BLOCKING
    assert "Stored as scan" in capsys.readouterr().out
    import sqlite3

    con = sqlite3.connect(tmp_path / "cli.db")
    assert con.execute("select count(*) from findings").fetchone()[0] == 1
    assert con.execute("select source from scans").fetchone()[0] == "cli"


@pytest.mark.skipif(os.name == "nt", reason="POSIX fake scanner")
def test_check_runs_without_web_or_db_dependencies(fake_gitleaks, tmp_path):
    """CI installs only PyYAML: `check` must not import SQLAlchemy/FastAPI."""
    code = (
        "import sys; sys.modules['sqlalchemy'] = None; sys.modules['fastapi'] = None; "
        "sys.modules['uvicorn'] = None; from secretsentinel.cli import main; "
        f"sys.exit(main(['check', {str(tmp_path)!r}, '--mode', 'dir', '--gitleaks', {fake_gitleaks.path!r}]))"
    )
    env = dict(os.environ, PYTHONPATH=str(BACKEND), FAKE_GITLEAKS_SCENARIO="clean")
    proc = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True)
    assert proc.returncode == 0, proc.stderr.decode()


def test_rules_commands(capsys):
    assert main(["rules", "list", "--format", "json"]) == EXIT_PASS
    data = json.loads(capsys.readouterr().out)
    assert any(r["rule_id"] == "web3-mnemonic-assignment" for r in data["rules"])
    assert main(["rules", "digest"]) == EXIT_PASS
    assert "sha256:" in capsys.readouterr().out


def test_attest_disabled_by_default(capsys):
    assert main(["attest", "verify", "nothing.json"]) == EXIT_USAGE
