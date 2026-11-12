"""`secretsentinel hook`: installs a managed pre-commit hook and never touches someone else's."""

import os
import subprocess

import pytest

from secretsentinel import cli
from secretsentinel.core.errors import SecretSentinelError
from secretsentinel.fixtures import synth
from secretsentinel.services import hook

from .conftest import git

KEY = synth("hex64", "hook-test")


def test_install_writes_a_managed_executable_hook(git_repo, monkeypatch):
    monkeypatch.setenv("GITLEAKS_PATH", "/opt/tools/gitleaks")
    path = hook.install(git_repo)
    assert path == (git_repo / ".git" / "hooks" / "pre-commit").resolve()
    raw = path.read_bytes()
    text = raw.decode()
    assert text.startswith("#!/bin/sh\n") and hook.MARKER in text and b"\r\n" not in raw
    assert "-m secretsentinel check \"$repo\" --mode staged --no-size-limit" in text
    assert "GITLEAKS_PATH=/opt/tools/gitleaks; export GITLEAKS_PATH" in text
    if os.name != "nt":
        assert os.access(path, os.X_OK)
    assert hook.install(git_repo) == path  # reinstalling over our own hook is fine


def test_someone_elses_hook_is_never_overwritten_or_removed(git_repo):
    path = git_repo / ".git" / "hooks" / "pre-commit"
    path.parent.mkdir(exist_ok=True)
    path.write_text("#!/bin/sh\necho mine\n")
    with pytest.raises(SecretSentinelError):
        hook.install(git_repo)
    with pytest.raises(SecretSentinelError):
        hook.uninstall(git_repo)
    assert path.read_text() == "#!/bin/sh\necho mine\n"


def test_uninstall_removes_only_our_hook(git_repo):
    hook.install(git_repo)
    assert hook.uninstall(git_repo) is not None
    assert hook.uninstall(git_repo) is None


def test_respects_core_hooks_path(git_repo):
    git(git_repo, "config", "core.hooksPath", ".githooks")
    assert hook.install(git_repo) == (git_repo / ".githooks" / "pre-commit").resolve()


def test_cli_reports_non_repositories(tmp_path, capsys):
    assert cli.main(["hook", "install", str(tmp_path)]) == cli.EXIT_USAGE
    assert "Not a Git repository" in capsys.readouterr().err


@pytest.mark.gitleaks
def test_hook_blocks_a_commit_with_a_staged_secret(git_repo, gitleaks_bin, monkeypatch):
    monkeypatch.setenv("GITLEAKS_PATH", gitleaks_bin)
    hook.install(git_repo)
    env = dict(os.environ, GIT_AUTHOR_NAME="T", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="T", GIT_COMMITTER_EMAIL="t@example.invalid")

    def commit(msg):
        return subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", msg],
                              cwd=git_repo, env=env, capture_output=True, text=True)

    (git_repo / "app.env").write_text(f"PRIVATE_KEY=0x{KEY}\n")
    git(git_repo, "add", "app.env")
    blocked = commit("leak")
    assert blocked.returncode != 0
    assert KEY not in blocked.stdout + blocked.stderr  # the hook output is redacted
    assert git(git_repo, "rev-list", "--count", "HEAD") == "1"  # nothing was committed

    git(git_repo, "rm", "-q", "--cached", "app.env")
    (git_repo / "notes.md").write_text("no secrets here\n")
    git(git_repo, "add", "notes.md")
    assert commit("clean").returncode == 0
