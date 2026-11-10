"""Shared fixtures.

* ``gitleaks_bin`` - a real Gitleaks executable (GITLEAKS_PATH or PATH);
  tests using it are skipped when none is installed. CI always installs one.
* ``fake_gitleaks`` - a scripted stand-in for deterministic error-path tests
  (missing binary, crash, timeout, malformed reports, unredacted output).
* ``fixture_root`` / ``canaries`` - synthetic fixtures materialised at test
  time and the exact values that must never appear in any output.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from secretsentinel.core.config import Settings, set_settings
from secretsentinel.database import reset_engine
from secretsentinel.fixtures import all_canaries, materialize

POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="fake scanner script needs a POSIX shebang")


def _find_gitleaks() -> str | None:
    env = os.environ.get("GITLEAKS_PATH")
    if env and Path(env).is_file():
        return env
    return shutil.which("gitleaks")


@pytest.fixture(scope="session")
def gitleaks_bin() -> str:
    path = _find_gitleaks()
    if not path:
        pytest.skip("real Gitleaks not installed (set GITLEAKS_PATH)")
    return path


@pytest.fixture(scope="session")
def fixture_set(tmp_path_factory):
    return materialize(tmp_path_factory.mktemp("fixtures") / "root")


@pytest.fixture(scope="session")
def fixture_root(fixture_set) -> Path:
    return fixture_set.root.resolve()


@pytest.fixture(scope="session")
def canaries() -> set[str]:
    return all_canaries()


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    """Keep every test away from the user's real database and config."""
    monkeypatch.setenv("DB_URL", f"sqlite:///{(tmp_path / 'isolated.db').as_posix()}")
    for var in ("API_TOKEN", "INGEST_TOKEN", "SCAN_ROOT_ALLOWLIST", "ENABLE_BLOCKCHAIN", "FAIL_ON"):
        monkeypatch.delenv(var, raising=False)
    set_settings(None)
    yield
    reset_engine()
    set_settings(None)


FAKE_SCRIPT = textwrap.dedent(
    """\
    #!{python}
    import json, os, sys, time
    args = sys.argv[1:]
    scenario = os.environ.get("FAKE_GITLEAKS_SCENARIO", "clean")
    log = os.environ.get("FAKE_GITLEAKS_ARGV_LOG")
    if log:
        with open(log, "a") as fh:
            fh.write(json.dumps(args) + "\\n")
    if args[:1] == ["version"]:
        print("garbage" if scenario == "bad-version" else "v8.30.1")
        sys.exit(0)
    def opt(name):
        return args[args.index(name) + 1] if name in args else None
    report = opt("--report-path")
    exit_code = int(opt("--exit-code") or 1)
    if scenario == "timeout":
        time.sleep(60)
    if scenario == "crash":
        sys.stderr.write("panic: something failed\\n"); sys.exit(2)
    if scenario == "config-error":
        sys.stderr.write("unable to load config: toml parse error\\n"); sys.exit(1)
    if scenario == "no-report":
        sys.exit(0)
    if scenario == "bad-json":
        open(report, "w").write("{{not json"); sys.exit(0)
    if scenario == "leaks-empty":
        open(report, "w").write("[]"); sys.exit(exit_code)
    records = []
    path = os.environ.get("FAKE_GITLEAKS_RECORDS")
    if path:
        records = json.load(open(path))
    open(report, "w").write(json.dumps(records))
    sys.exit(exit_code if records else 0)
    """
)


@pytest.fixture
def fake_gitleaks(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("fake scanner needs POSIX")
    script = tmp_path / "fake-gitleaks"
    script.write_text(FAKE_SCRIPT.format(python=sys.executable))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)

    class Fake:
        path = str(script)

        def scenario(self, name: str) -> None:
            monkeypatch.setenv("FAKE_GITLEAKS_SCENARIO", name)

        def records(self, records: list) -> None:
            p = tmp_path / "fake-records.json"
            p.write_text(json.dumps(records))
            monkeypatch.setenv("FAKE_GITLEAKS_RECORDS", str(p))
            monkeypatch.setenv("FAKE_GITLEAKS_SCENARIO", "records")

        def argv_log(self) -> Path:
            p = tmp_path / "argv.log"
            monkeypatch.setenv("FAKE_GITLEAKS_ARGV_LOG", str(p))
            return p

    return Fake()


def raw_record(canary: str, **overrides) -> dict:
    """A Gitleaks-shaped record whose sensitive fields hold a canary value."""
    rec = {
        "RuleID": "web3-evm-private-key-assignment",
        "Description": "desc",
        "StartLine": 3,
        "EndLine": 3,
        "StartColumn": 1,
        "EndColumn": 90,
        "Match": f"PRIVATE_KEY=0x{canary}",
        "Secret": canary,
        "File": "src/config.js",
        "SymlinkFile": "",
        "Commit": "",
        "Entropy": 3.8,
        "Author": "Someone",
        "Email": "someone@example.invalid",
        "Date": "",
        "Message": f"oops {canary}",
        "Tags": ["web3"],
        "Fingerprint": f"src/config.js:web3-evm-private-key-assignment:3",
    }
    rec.update(overrides)
    return rec


@pytest.fixture
def settings_factory(tmp_path):
    def make(gitleaks_path: str = "gitleaks", **kw) -> Settings:
        base = Settings(gitleaks_path=gitleaks_path, db_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
        return base.with_overrides(**kw)

    return make


def git(cwd: Path, *args: str) -> str:
    env = dict(os.environ)
    env.update(
        GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="t@example.invalid",
        GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="t@example.invalid",
    )
    out = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
        cwd=cwd, capture_output=True, check=True, env=env,
    )
    return out.stdout.decode().strip()


@pytest.fixture
def git_repo(tmp_path) -> Path:
    if not shutil.which("git"):
        pytest.skip("git not installed")
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "README.md").write_text("hello\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--no-verify", "-m", "init")
    return repo.resolve()
