"""Create a disposable demo repository with SYNTHETIC leaks and Git history.

Layout produced (all values synthetic, derived from public labels):

* commit 1 - clean app skeleton
* commit 2 - adds ``.env`` with a synthetic DEPLOYER_PRIVATE_KEY and
  ``src/config.js`` with a synthetic Infura project key in an RPC URL
* commit 3 - deletes ``.env`` (the leak now exists ONLY in history: T03)
* untracked ``scripts/seed.js`` with a synthetic mnemonic (dir mode only: T04)

Nothing here runs repository code; Git hooks are bypassed for the demo commits.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from ..core.errors import ErrorCode, SecretSentinelError
from ..fixtures import synth
from .scanner import hardened_env, resolve_executable

BANNER = "SYNTHETIC DEMO VALUE - NOT A REAL CREDENTIAL"

_DEMO_VALUES = {
    "private_key": ("hex64", "demo-deployer"),
    "infura": ("hex32", "demo-infura"),
    "mnemonic": ("mnemonic12", "demo-seed"),
}


def demo_canaries() -> set[str]:
    return {synth(kind, label) for kind, label in _DEMO_VALUES.values()}


def _value(name: str) -> str:
    kind, label = _DEMO_VALUES[name]
    return synth(kind, label)


def create_demo_repo(dest: Path, git_path: str = "git") -> Path:
    git = resolve_executable(git_path, ErrorCode.GIT_NOT_FOUND)
    dest = dest.expanduser()
    if dest.exists() and any(dest.iterdir()):
        raise SecretSentinelError(ErrorCode.INVALID_STATE, "Destination must be empty.")
    dest.mkdir(parents=True, exist_ok=True)
    dest = dest.resolve()
    hooks_dir = tempfile.mkdtemp(prefix="secretsentinel-nohooks-")
    env = hardened_env()
    env.update(
        {
            "GIT_AUTHOR_NAME": "SecretSentinel Demo",
            "GIT_AUTHOR_EMAIL": "demo@example.invalid",
            "GIT_COMMITTER_NAME": "SecretSentinel Demo",
            "GIT_COMMITTER_EMAIL": "demo@example.invalid",
        }
    )

    def git_run(*args: str) -> None:
        cmd = [git, "-c", f"core.hooksPath={hooks_dir}", "-c", "commit.gpgsign=false", "-C", str(dest), *args]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=60, shell=False, env=env, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            raise SecretSentinelError(ErrorCode.GIT_NOT_FOUND) from None
        if proc.returncode != 0:
            raise SecretSentinelError(ErrorCode.INTERNAL_ERROR, "Git command failed while creating the demo.")

    def write(rel: str, text: str) -> None:
        path = dest / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    try:
        git_run("init", "-q")
        write(
            "README.md",
            "# SecretSentinel demo repository\n\nDisposable repository with SYNTHETIC leaks for demonstrations.\n"
            "Never put real credentials here.\n",
        )
        write("src/app.js", 'import { RPC_URL } from "./config.js";\n\nconsole.log("connecting to", RPC_URL);\n')
        write("src/config.js", 'export const RPC_URL = process.env.RPC_URL ?? "https://rpc.sepolia.org";\n')
        git_run("add", "-A")
        git_run("commit", "-q", "--no-verify", "-m", "Initial commit")

        write(".env", f"# {BANNER}\nDEPLOYER_PRIVATE_KEY=0x{_value('private_key')}\n")
        write(
            "src/config.js",
            f"// {BANNER}\nexport const RPC_URL = \"https://mainnet.infura.io/v3/{_value('infura')}\";\n",
        )
        git_run("add", "-A")
        git_run("commit", "-q", "--no-verify", "-m", "Add deployment configuration")

        git_run("rm", "-q", "--cached", ".env")
        os.remove(dest / ".env")
        write(".gitignore", ".env\n")
        git_run("add", "-A")
        git_run("commit", "-q", "--no-verify", "-m", "Remove .env (history still contains it)")

        write("scripts/seed.js", f"// {BANNER}\nconst mnemonic = \"{_value('mnemonic')}\";\nexport default mnemonic;\n")
    finally:
        try:
            os.rmdir(hooks_dir)
        except OSError:
            pass
    return dest
