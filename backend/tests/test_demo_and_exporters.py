"""Demo repository generator and exporter edge cases."""

import csv
import io
import shutil

import pytest

from secretsentinel.core.config import Settings
from secretsentinel.services.demo import create_demo_repo, demo_canaries
from secretsentinel.services.exporters import FAILED_MESSAGE, result_line, to_csv, to_text
from secretsentinel.services.scanner import ScanRequest, run_scan
from secretsentinel.services.types import SafeFinding, ScanOutcome

from .conftest import git


@pytest.fixture
def demo(tmp_path):
    if not shutil.which("git"):
        pytest.skip("git missing")
    return create_demo_repo(tmp_path / "demo")


def test_demo_repo_layout(demo):
    log = git(demo, "log", "--oneline")
    assert len(log.splitlines()) == 3
    assert not (demo / ".env").exists()  # history-only leak
    assert "scripts/seed.js" in git(demo, "status", "--porcelain", "--untracked-files=all")


def test_demo_refuses_non_empty_destination(tmp_path):
    (tmp_path / "x").mkdir()
    (tmp_path / "x" / "file").write_text("x")
    from secretsentinel.core.errors import SecretSentinelError

    with pytest.raises(SecretSentinelError):
        create_demo_repo(tmp_path / "x")


@pytest.mark.gitleaks
def test_demo_scan_finds_all_three_leaks(demo, gitleaks_bin):
    o = run_scan(ScanRequest(target=demo, mode="both"), Settings(gitleaks_path=gitleaks_bin, db_url="sqlite://"))
    rules = {(f.rule_id, f.relative_path) for f in o.findings}
    assert ("web3-evm-private-key-assignment", ".env") in rules
    assert ("web3-mnemonic-assignment", "scripts/seed.js") in rules
    assert ("web3-infura-rpc-url", "src/config.js") in rules
    assert len(demo_canaries()) == 3


def test_csv_neutralises_formula_injection():
    o = ScanOutcome(mode="dir", status="completed", findings=[
        SafeFinding(rule_id="github-pat", relative_path="=HYPERLINK(\"http://x\")", start_line=1, end_line=1)])
    rows = list(csv.reader(io.StringIO(to_csv(o))))
    assert rows[1][6].startswith("'=")


def test_result_wording_never_overclaims():
    failed = ScanOutcome(mode="dir", status="failed", error_code="SCAN_TIMEOUT")
    assert FAILED_MESSAGE in result_line(failed) and "PASS" not in result_line(failed)
    clean = ScanOutcome(mode="dir", status="completed", policy_result="pass")
    text = to_text(clean, "t")
    assert "No matching secrets detected in the scanned scope." in text
    assert "not a guarantee" in text and "secure" not in text.lower().replace("not a guarantee", "")
