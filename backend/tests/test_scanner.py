"""Scanner orchestration: state handling (SCAN-06), fail-closed behaviour (S3),
Git history/working tree modes (T03/T04), cancellation, and bypass resistance."""

import json
import threading
import time

import pytest

from secretsentinel.fixtures import synth
from secretsentinel.services.policy import Policy
from secretsentinel.services.scanner import ScanRequest, run_scan

from .conftest import git, raw_record

KEY = synth("hex64", "scanner-test")


def _scan(settings, target, mode="dir", **kw):
    return run_scan(ScanRequest(target=target, mode=mode, **kw), settings)


# ---------------------------------------------------------------- fake scanner

def test_T08_missing_scanner_fails_never_passes(settings_factory, tmp_path):
    o = _scan(settings_factory("/definitely/not/gitleaks"), tmp_path)
    assert o.status == "failed" and o.error_code == "SCANNER_NOT_FOUND"
    assert o.policy_result == "not_evaluated" and o.findings == []


def test_T09_timeout_fails_with_safe_error(settings_factory, fake_gitleaks, tmp_path):
    fake_gitleaks.scenario("timeout")
    start = time.monotonic()
    o = _scan(settings_factory(fake_gitleaks.path), tmp_path, timeout_seconds=1)
    assert time.monotonic() - start < 15
    assert o.status == "failed" and o.error_code == "SCAN_TIMEOUT" and o.policy_result == "not_evaluated"


@pytest.mark.parametrize(
    "scenario,code",
    [
        ("crash", "SCANNER_ERROR"),
        ("config-error", "INVALID_CONFIG"),
        ("no-report", "REPORT_PARSE_FAILED"),
        ("bad-json", "REPORT_PARSE_FAILED"),
        ("leaks-empty", "REPORT_PARSE_FAILED"),
        ("bad-version", "SCANNER_ERROR"),
    ],
)
def test_scanner_errors_fail_closed(settings_factory, fake_gitleaks, tmp_path, scenario, code):
    fake_gitleaks.scenario(scenario)
    o = _scan(settings_factory(fake_gitleaks.path), tmp_path)
    assert o.status == "failed", scenario
    assert o.error_code == code
    assert o.policy_result != "pass"


def test_clean_scan_passes_T01(settings_factory, fake_gitleaks, tmp_path):
    fake_gitleaks.scenario("clean")
    o = _scan(settings_factory(fake_gitleaks.path), tmp_path)
    assert (o.status, o.policy_result, o.total_findings) == ("completed", "pass", 0)


def test_unredacted_scanner_output_is_sanitized(settings_factory, fake_gitleaks, tmp_path):
    fake_gitleaks.records([raw_record(KEY, Unexpected=KEY)])
    o = _scan(settings_factory(fake_gitleaks.path), tmp_path)
    assert o.status == "completed" and o.blocking_findings == 1
    assert o.dropped_fields == 1
    assert any("not redacted" in w for w in o.warnings)
    assert KEY not in json.dumps([f.to_safe_dict() for f in o.findings])


def test_gitleaks_invocation_is_hardened(settings_factory, fake_gitleaks, tmp_path):
    log = fake_gitleaks.argv_log()
    fake_gitleaks.scenario("clean")
    _scan(settings_factory(fake_gitleaks.path), tmp_path)
    argv = [json.loads(line) for line in log.read_text().splitlines() if not line.startswith('["version"')]
    scan_args = argv[-1]
    assert scan_args[0] == "dir"
    for flag in ("--redact=100", "--ignore-gitleaks-allow", "--no-banner", "--report-format"):
        assert flag in scan_args
    ignore_dir = scan_args[scan_args.index("--gitleaks-ignore-path") + 1]
    assert str(tmp_path) not in ignore_dir  # never the target's own .gitleaksignore
    cfg = scan_args[scan_args.index("--config") + 1]
    assert not cfg.startswith(str(tmp_path))


def test_cancellation(settings_factory, fake_gitleaks, tmp_path):
    fake_gitleaks.scenario("timeout")
    ev = threading.Event()
    threading.Timer(0.5, ev.set).start()
    o = _scan(settings_factory(fake_gitleaks.path), tmp_path, timeout_seconds=30, cancel_event=ev)
    assert o.status == "cancelled" and o.error_code == "SCAN_CANCELLED"


def test_temp_files_removed(settings_factory, fake_gitleaks, tmp_path, monkeypatch):
    import tempfile as _tempfile

    created = []
    real = _tempfile.mkdtemp

    def spy(*a, **k):
        d = real(*a, **k)
        created.append(d)
        return d

    monkeypatch.setattr("secretsentinel.services.scanner.tempfile.mkdtemp", spy)
    fake_gitleaks.records([raw_record(KEY)])
    _scan(settings_factory(fake_gitleaks.path), tmp_path)
    fake_gitleaks.scenario("timeout")
    _scan(settings_factory(fake_gitleaks.path), tmp_path, timeout_seconds=1)
    from pathlib import Path

    assert created and all(not Path(d).exists() for d in created)


def test_git_mode_requires_git_repo(settings_factory, fake_gitleaks, tmp_path):
    fake_gitleaks.scenario("clean")
    o = _scan(settings_factory(fake_gitleaks.path), tmp_path, mode="git")
    assert o.status == "failed" and o.error_code == "UNSUPPORTED_REPO"


def test_git_subdirectory_rejected(settings_factory, fake_gitleaks, git_repo):
    (git_repo / "sub").mkdir()
    fake_gitleaks.scenario("clean")
    o = _scan(settings_factory(fake_gitleaks.path), (git_repo / "sub").resolve(), mode="git")
    assert o.error_code == "UNSUPPORTED_REPO"


@pytest.mark.parametrize("ref", ["--output=/tmp/pwn", "main..HEAD", "does-not-exist", "a b"])
def test_malicious_or_unknown_ref_rejected(settings_factory, fake_gitleaks, git_repo, ref):
    fake_gitleaks.scenario("clean")
    o = _scan(settings_factory(fake_gitleaks.path), git_repo, mode="git", since_ref=ref)
    assert o.status == "failed" and o.error_code == "INVALID_GIT_REF"


def test_policy_exclusions_filter_results(settings_factory, fake_gitleaks, tmp_path):
    fake_gitleaks.records([raw_record(KEY, File="vendor/lib.js"), raw_record(KEY, File="src/app.js")])
    o = _scan(settings_factory(fake_gitleaks.path), tmp_path, policy=Policy(exclude_paths=("vendor/**",)))
    assert [f.relative_path for f in o.findings] == ["src/app.js"]


# ---------------------------------------------------------------- real scanner

def _commit(repo, rel, text, msg):
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--no-verify", "-m", msg)


@pytest.mark.gitleaks
def test_T03_history_only_leak_found_by_git_not_dir(settings_factory, gitleaks_bin, git_repo):
    _commit(git_repo, ".env", f"PRIVATE_KEY=0x{KEY}\n", "add env")
    git(git_repo, "rm", "-q", ".env")
    git(git_repo, "commit", "-q", "--no-verify", "-m", "remove env")
    s = settings_factory(gitleaks_bin)
    assert _scan(s, git_repo, "dir").total_findings == 0
    o = _scan(s, git_repo, "git")
    assert o.status == "completed" and o.policy_result == "fail"
    f = o.findings[0]
    assert f.relative_path == ".env" and f.commit_sha and f.sources == ("git",)


@pytest.mark.gitleaks
def test_T04_uncommitted_leak_found_by_dir_not_git(settings_factory, gitleaks_bin, git_repo):
    (git_repo / "wip.env").write_text(f"DEPLOYER_PRIVATE_KEY={KEY}\n")
    s = settings_factory(gitleaks_bin)
    assert _scan(s, git_repo, "git").total_findings == 0
    o = _scan(s, git_repo, "dir")
    assert [f.relative_path for f in o.findings] == ["wip.env"]


@pytest.mark.gitleaks
def test_both_mode_deduplicates_dir_and_git(settings_factory, gitleaks_bin, git_repo):
    _commit(git_repo, "cfg/.env", f"PRIVATE_KEY=0x{KEY}\n", "leak")
    o = _scan(settings_factory(gitleaks_bin), git_repo, "both")
    assert o.total_findings == 1
    assert o.findings[0].sources == ("dir", "git") and o.findings[0].commit_sha


@pytest.mark.gitleaks
def test_range_scan_only_covers_new_commits(settings_factory, gitleaks_bin, git_repo):
    _commit(git_repo, "old.env", f"PRIVATE_KEY=0x{KEY}\n", "old leak")
    base = git(git_repo, "rev-parse", "HEAD")
    _commit(git_repo, "new.env", f"SIGNER_KEY=0x{synth('hex64', 'range-new')}\n", "new leak")
    o = _scan(settings_factory(gitleaks_bin), git_repo, "git", since_ref=base)
    assert [f.relative_path for f in o.findings] == ["new.env"]
    assert o.scope.startswith("commits:")


@pytest.mark.gitleaks
def test_inline_allow_comment_cannot_bypass(settings_factory, gitleaks_bin, tmp_path):
    (tmp_path / "a.env").write_text(f"PRIVATE_KEY=0x{KEY} # gitleaks:allow\n")
    o = _scan(settings_factory(gitleaks_bin), tmp_path, "dir")
    assert o.blocking_findings == 1


@pytest.mark.gitleaks
def test_repo_gitleaksignore_and_config_are_not_honoured(settings_factory, gitleaks_bin, tmp_path):
    (tmp_path / "a.env").write_text(f"PRIVATE_KEY=0x{KEY}\n")
    (tmp_path / ".gitleaksignore").write_text("a.env:web3-evm-private-key-assignment:1\n")
    (tmp_path / ".gitleaks.toml").write_text('[allowlist]\npaths = [".*"]\n')
    o = _scan(settings_factory(gitleaks_bin), tmp_path, "dir")
    # Repo .gitleaks.toml is ignored (our --config wins), so the leak is still seen by
    # generic rules; the repo .gitleaksignore (always read by Gitleaks) is itself a blocking finding.
    rules = {f.rule_id: f for f in o.findings}
    assert rules["secretsentinel-gitleaksignore-present"].blocking
    assert o.policy_result == "fail"


@pytest.mark.gitleaks
def test_gitleaksignore_finding_can_be_reviewed_and_suppressed(settings_factory, gitleaks_bin, tmp_path):
    from datetime import date, timedelta

    from secretsentinel.services.policy import Suppression

    (tmp_path / ".gitleaksignore").write_text("\n")
    sup = Suppression(id="S1", rule_id="secretsentinel-gitleaksignore-present", path=".gitleaksignore",
                      reason="Empty file kept for another tool", reviewer="sec-team", expires=date.today() + timedelta(days=30))
    o = _scan(settings_factory(gitleaks_bin), tmp_path, "dir", policy=Policy(suppressions=[sup]))
    assert o.policy_result == "pass" and o.suppressed_findings == 1


@pytest.mark.gitleaks
def test_excluded_paths_not_scanned(settings_factory, gitleaks_bin, tmp_path):
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "a.env").write_text(f"PRIVATE_KEY=0x{KEY}\n")
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "out.env").write_text(f"PRIVATE_KEY=0x{KEY}\n")
    o = _scan(settings_factory(gitleaks_bin), tmp_path, "dir", policy=Policy(exclude_paths=("build/",)))
    assert o.total_findings == 0


@pytest.mark.gitleaks
def test_records_versions_and_digests(settings_factory, gitleaks_bin, tmp_path):
    o = _scan(settings_factory(gitleaks_bin), tmp_path, "dir")
    assert o.scanner_version and o.ruleset_digest.startswith("sha256:") and o.policy_digest.startswith("sha256:")


@pytest.mark.gitleaks
def test_binary_and_unicode_files_do_not_break_scan(settings_factory, gitleaks_bin, tmp_path):
    (tmp_path / "blob.bin").write_bytes(bytes(range(256)) * 100)
    (tmp_path / "unicode.txt").write_bytes("naïve ✓ \udcff".encode("utf-8", "surrogateescape"))
    (tmp_path / "long.txt").write_text("a" * 2_000_000)
    o = _scan(settings_factory(gitleaks_bin), tmp_path, "dir")
    assert o.status == "completed"


# ---------------------------------------------------------------- staged (pre-commit)

def test_staged_command_uses_pre_commit_flags(tmp_path):
    from secretsentinel.services.scanner import STAGED_FLAGS, build_gitleaks_command

    cmd = build_gitleaks_command("gitleaks", "git", tmp_path / "c.toml", tmp_path / "r.json", tmp_path, 10, None, STAGED_FLAGS)
    assert cmd[1] == "git" and cmd[-2:] == ["--pre-commit", "--staged"]
    assert "--redact=100" in cmd and "--log-opts" not in cmd


def test_staged_mode_needs_repository_root(settings_factory, fake_gitleaks, git_repo):
    (git_repo / "sub").mkdir()
    fake_gitleaks.scenario("clean")
    o = _scan(settings_factory(fake_gitleaks.path), (git_repo / "sub").resolve(), mode="staged")
    assert o.status == "failed" and o.error_code == "UNSUPPORTED_REPO"


@pytest.mark.gitleaks
def test_staged_mode_scans_only_the_index(settings_factory, gitleaks_bin, git_repo):
    s = settings_factory(gitleaks_bin)
    (git_repo / "app.env").write_text(f"PRIVATE_KEY=0x{KEY}\n")
    assert _scan(s, git_repo, "staged").total_findings == 0  # written but not staged
    git(git_repo, "add", "app.env")
    o = _scan(s, git_repo, "staged")
    assert o.status == "completed" and o.policy_result == "fail" and o.scope == "staged-changes"
    f = o.findings[0]
    assert f.relative_path == "app.env" and f.sources == ("git",) and f.commit_sha is None
    git(git_repo, "commit", "-q", "--no-verify", "-m", "leak")
    assert _scan(s, git_repo, "staged").total_findings == 0  # committed: nothing staged any more
