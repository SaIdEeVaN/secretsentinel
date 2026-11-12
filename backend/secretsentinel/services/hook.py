"""Install or remove a Git pre-commit hook that scans staged changes.

The hook runs ``secretsentinel check <repo> --mode staged`` with the same
Python interpreter that installed it, so it works from editors and from Git for
Windows (whose hooks run under ``sh``) even when ``secretsentinel`` is not on
PATH. It blocks the commit on blocking findings and also when the scan cannot
run (fail closed); ``git commit --no-verify`` skips it deliberately.

A hook written by someone else is never overwritten or removed.
"""

from __future__ import annotations

import os
import shlex
import stat
import subprocess
import sys
from pathlib import Path

from ..core.errors import ErrorCode, SecretSentinelError

MARKER = "# secretsentinel pre-commit hook (managed; remove with: secretsentinel hook uninstall)"
# Settings worth freezing into the hook: a commit from an editor may not see the shell's variables.
_CARRIED_ENV = ("GITLEAKS_PATH", "SECRETSENTINEL_RULES_DIR")


def _hook_path(repo: Path, git: str = "git") -> Path:
    """Where Git looks for this repository's pre-commit hook (respects core.hooksPath)."""
    try:
        out = subprocess.run(
            [git, "-C", str(repo), "rev-parse", "--git-path", "hooks/pre-commit"],
            capture_output=True, text=True, timeout=15, check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SecretSentinelError(ErrorCode.UNSUPPORTED_REPO, "Not a Git repository (or Git is not installed).") from exc
    # Relative to the repository unless core.hooksPath is absolute (works on old Git too).
    return (repo / out.stdout.strip()).resolve()


def _posix(path: str) -> str:
    # Git for Windows runs hooks with sh, which accepts C:/... paths.
    return Path(path).as_posix() if os.name == "nt" else path


def render_hook(python: str | None = None, env: dict[str, str] | None = None) -> str:
    python = _posix(python or sys.executable)
    env = env if env is not None else {k: os.environ[k] for k in _CARRIED_ENV if os.environ.get(k)}
    lines = [
        "#!/bin/sh",
        MARKER,
        "# Blocks the commit if staged changes contain blocking findings, or if the scan cannot run.",
        "# Matched values are redacted. Skip once, deliberately: git commit --no-verify",
    ]
    for key in _CARRIED_ENV:
        if key in env:
            lines.append(f"{key}={shlex.quote(_posix(env[key]))}; export {key}")
    lines += [
        'repo="$(git rev-parse --show-toplevel)" || exit 1',
        f'exec {shlex.quote(python)} -m secretsentinel check "$repo" --mode staged --no-size-limit',
        "",
    ]
    return "\n".join(lines)


def is_managed(path: Path) -> bool:
    try:
        return MARKER in path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False


def install(repo: Path, git: str = "git") -> Path:
    path = _hook_path(repo, git)
    if path.exists() and not is_managed(path):
        raise SecretSentinelError(
            ErrorCode.VALIDATION_ERROR,
            f"{path} already exists and was not written by SecretSentinel. Add this line to it instead: "
            f"{_posix(sys.executable)} -m secretsentinel check \"$(git rev-parse --show-toplevel)\" --mode staged --no-size-limit",
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(render_hook().encode("utf-8"))  # bytes: keep LF endings on Windows for sh
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def uninstall(repo: Path, git: str = "git") -> Path | None:
    path = _hook_path(repo, git)
    if not path.exists():
        return None
    if not is_managed(path):
        raise SecretSentinelError(ErrorCode.VALIDATION_ERROR, f"{path} was not written by SecretSentinel; leaving it alone.")
    path.unlink()
    return path
