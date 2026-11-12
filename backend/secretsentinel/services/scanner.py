"""Scanner orchestration: Gitleaks execution -> sanitizer -> classifier -> policy.

Pipeline (PRD 12.1):

1. Validate a canonical target directory (callers enforce allowlists).
2. Determine dir/git/both and check Git availability.
3. Launch the Gitleaks executable with an argument list (never ``shell=True``)
   under a timeout, with ``--redact=100`` and a SecretSentinel-controlled
   config. Repository-controlled ``.gitleaksignore`` files and inline
   ``gitleaks:allow`` comments are disabled, so a change under review cannot
   silently exempt itself.
4. Capture the report in a private temporary directory outside the target.
5. Parse into memory and pass every record through the deny-by-default
   sanitizer. Raw records are never serialized.
6. Remove temporary files in ``finally`` (also on timeout/cancel).
7. Evaluate the blocking policy separately; a failed scan is never a pass.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from .. import __version__
from ..core.config import Settings
from ..core.errors import ErrorCode, SecretSentinelError
from ..core.log import log_event
from ..core.security import check_repo_size, is_commit_sha, validate_ref_syntax
from .deduplicator import deduplicate
from .finding_classifier import classify_all
from .policy import Policy, Suppression, evaluate, is_excluded
from .rules import Ruleset, load_ruleset
from .sanitizer import SanitizeStats, sanitize_report
from .types import SafeFinding, ScanOutcome

LEAK_EXIT_CODE = 3
_VERSION_RE = re.compile(r"v?(\d+\.\d+\.\d+)")
_MAX_REPORT_BYTES = 256 * 1024 * 1024
MIN_GITLEAKS = (8, 25, 0)
# `git log` options appended by SecretSentinel. --no-ext-diff/--no-textconv stop
# repository-local diff drivers from executing programs (invariant S4).
_GIT_SAFE_LOG_OPTS = ["--no-ext-diff", "--no-textconv", "--diff-filter=tuxdb"]
# `gitleaks git --pre-commit --staged` reads `git diff --staged`: only the index.
STAGED_FLAGS = ["--pre-commit", "--staged"]
_GIT_CONFIG_OVERRIDES = [("core.fsmonitor", "false"), ("core.pager", "cat")]
_LOGGING_LEVEL_INFO = 20
_LOGGING_LEVEL_WARN = 30


@dataclass
class ScanRequest:
    target: Path
    mode: str
    since_ref: str | None = None
    fail_on: str = "high"
    policy: Policy = field(default_factory=Policy.empty)
    extra_suppressions: list[Suppression] = field(default_factory=list)
    timeout_seconds: int = 120
    max_file_mb: int = 10
    cancel_event: threading.Event | None = None
    enforce_size_limit: bool = True


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hardened_env() -> dict[str, str]:
    env = dict(os.environ)
    # Never let an inherited config redirect Gitleaks away from our --config.
    env.pop("GITLEAKS_CONFIG", None)
    env.pop("GITLEAKS_CONFIG_TOML", None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_PAGER"] = "cat"
    env["PAGER"] = "cat"
    env["NO_COLOR"] = "1"
    try:
        start = int(env.get("GIT_CONFIG_COUNT", "0"))
    except ValueError:
        start = 0
    for offset, (key, value) in enumerate(_GIT_CONFIG_OVERRIDES):
        env[f"GIT_CONFIG_KEY_{start + offset}"] = key
        env[f"GIT_CONFIG_VALUE_{start + offset}"] = value
    env["GIT_CONFIG_COUNT"] = str(start + len(_GIT_CONFIG_OVERRIDES))
    return env


def resolve_executable(name_or_path: str, error: ErrorCode) -> str:
    candidate = Path(name_or_path).expanduser()
    if candidate.parent != Path(".") or candidate.is_absolute():
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate.resolve())
        raise SecretSentinelError(error)
    found = shutil.which(name_or_path)
    if not found:
        raise SecretSentinelError(error)
    return found


@lru_cache(maxsize=16)
def _gitleaks_version_cached(path: str, mtime: float) -> str:
    try:
        proc = subprocess.run(
            [path, "version"],
            capture_output=True,
            timeout=20,
            shell=False,
            env=hardened_env(),
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        raise SecretSentinelError(ErrorCode.SCANNER_NOT_FOUND) from None
    match = _VERSION_RE.search(proc.stdout.decode("utf-8", "replace")[:200])
    if proc.returncode != 0 or not match:
        raise SecretSentinelError(ErrorCode.SCANNER_ERROR, "Could not determine Gitleaks version.")
    return match.group(1)


def gitleaks_version(path: str) -> str:
    try:
        mtime = os.stat(path).st_mtime
    except OSError:
        raise SecretSentinelError(ErrorCode.SCANNER_NOT_FOUND) from None
    return _gitleaks_version_cached(path, mtime)


def version_tuple(version: str) -> tuple[int, int, int]:
    return tuple(int(x) for x in version.split(".")[:3])  # type: ignore[return-value]


def _git(git: str, target: Path, *args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            [git, "-C", str(target), *args],
            capture_output=True,
            timeout=timeout,
            shell=False,
            env=hardened_env(),
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        raise SecretSentinelError(ErrorCode.GIT_NOT_FOUND) from None


def git_toplevel(git: str, target: Path) -> Path | None:
    proc = _git(git, target, "rev-parse", "--show-toplevel")
    if proc.returncode != 0:
        return None
    out = proc.stdout.decode("utf-8", "replace").strip()
    try:
        return Path(out).resolve()
    except OSError:
        return None


def git_resolve_commit(git: str, target: Path, ref: str) -> str:
    validate_ref_syntax(ref)
    proc = _git(git, target, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    sha = proc.stdout.decode("ascii", "replace").strip().lower()
    if proc.returncode != 0 or not is_commit_sha(sha):
        raise SecretSentinelError(ErrorCode.INVALID_GIT_REF)
    return sha


def git_head(git: str, target: Path) -> str | None:
    proc = _git(git, target, "rev-parse", "--verify", "--quiet", "HEAD^{commit}")
    sha = proc.stdout.decode("ascii", "replace").strip().lower()
    return sha if proc.returncode == 0 and is_commit_sha(sha) else None


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
                timeout=10,
                shell=False,
            )
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.SubprocessError:
        pass


def _run_gitleaks(
    cmd: list[str],
    cwd: Path,
    workdir: Path,
    deadline: float,
    cancel_event: threading.Event | None,
) -> int:
    stderr_path = workdir / "stderr.log"
    popen_kwargs: dict = {}
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    else:
        popen_kwargs["start_new_session"] = True
    with open(stderr_path, "wb") as err:
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(cwd),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=err,
                env=hardened_env(),
                shell=False,
                **popen_kwargs,
            )
        except OSError:
            raise SecretSentinelError(ErrorCode.SCANNER_NOT_FOUND) from None
        while True:
            try:
                return proc.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                if cancel_event is not None and cancel_event.is_set():
                    _kill_tree(proc)
                    raise SecretSentinelError(ErrorCode.SCAN_CANCELLED) from None
                if time.monotonic() > deadline:
                    _kill_tree(proc)
                    raise SecretSentinelError(ErrorCode.SCAN_TIMEOUT) from None


def _classify_failure(workdir: Path) -> ErrorCode:
    """Map a Gitleaks failure to a controlled code. stderr is read, never emitted."""
    try:
        with open(workdir / "stderr.log", "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 8192))
            tail = fh.read().decode("utf-8", "replace").lower()
    except OSError:
        return ErrorCode.SCANNER_ERROR
    if "config" in tail and ("unable to load" in tail or "failed to load" in tail or "toml" in tail or "regex" in tail):
        return ErrorCode.INVALID_CONFIG
    if "not a git repository" in tail or "does not have any commits" in tail:
        return ErrorCode.UNSUPPORTED_REPO
    return ErrorCode.SCANNER_ERROR


def _read_report(path: Path, return_code: int) -> list:
    if not path.is_file():
        raise SecretSentinelError(ErrorCode.REPORT_PARSE_FAILED)
    if path.stat().st_size > _MAX_REPORT_BYTES:
        raise SecretSentinelError(ErrorCode.REPORT_PARSE_FAILED)
    try:
        data = json.loads(path.read_bytes().decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise SecretSentinelError(ErrorCode.REPORT_PARSE_FAILED) from None
    if not isinstance(data, list):
        raise SecretSentinelError(ErrorCode.REPORT_PARSE_FAILED)
    if return_code == LEAK_EXIT_CODE and not data:
        # Gitleaks said "leaks found" but produced no records: inconsistent -> fail closed.
        raise SecretSentinelError(ErrorCode.REPORT_PARSE_FAILED)
    return data


def build_gitleaks_command(
    gitleaks: str,
    mode: str,
    config_path: Path,
    report_path: Path,
    ignore_dir: Path,
    max_file_mb: int,
    log_opts: list[str] | None = None,
    extra: list[str] | None = None,
) -> list[str]:
    cmd = [
        gitleaks,
        mode,
        ".",
        "--config",
        str(config_path),
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
        "--redact=100",
        "--no-banner",
        "--no-color",
        "--log-level",
        "error",
        "--exit-code",
        str(LEAK_EXIT_CODE),
        "--max-target-megabytes",
        str(max_file_mb),
        "--gitleaks-ignore-path",
        str(ignore_dir),
        "--ignore-gitleaks-allow",
    ]
    if mode == "git" and log_opts:
        cmd += ["--log-opts", " ".join(log_opts)]
    if extra:
        cmd += extra
    return cmd


IGNORE_FILE_RULE = "secretsentinel-gitleaksignore-present"


def _ignore_file_findings(target: Path) -> list[SafeFinding]:
    """Gitleaks always honours ``<source>/.gitleaksignore`` (no flag disables it).

    A repository-controlled ignore file could therefore hide findings from the
    gate, so its presence is reported as a finding of its own. Legitimate
    exceptions belong in reviewed, expiring ``.secretsentinel.yml`` suppressions.
    """
    try:
        os.lstat(target / ".gitleaksignore")
    except OSError:
        return []
    return [SafeFinding(rule_id=IGNORE_FILE_RULE, relative_path=".gitleaksignore", start_line=0, end_line=0, sources=("policy",))]


def run_scan(req: ScanRequest, settings: Settings, ruleset: Ruleset | None = None) -> ScanOutcome:
    outcome = ScanOutcome(mode=req.mode, fail_on=req.fail_on, started_at=_utcnow(), secretsentinel_version=__version__)
    outcome.policy_digest = req.policy.digest
    started = time.monotonic()
    deadline = started + req.timeout_seconds
    stats = SanitizeStats()
    try:
        if req.mode not in ("dir", "git", "both", "staged"):
            raise SecretSentinelError(ErrorCode.VALIDATION_ERROR)
        ruleset = ruleset or load_ruleset()
        outcome.ruleset_version = ruleset.version
        outcome.ruleset_digest = ruleset.digest
        gitleaks = resolve_executable(settings.gitleaks_path, ErrorCode.SCANNER_NOT_FOUND)
        outcome.scanner_version = gitleaks_version(gitleaks)
        if version_tuple(outcome.scanner_version) < MIN_GITLEAKS:
            outcome.warnings.append("gitleaks older than 8.25.0: some ruleset features may be ignored")
        if req.enforce_size_limit:
            check_repo_size(req.target, settings.max_repo_mb, settings.max_repo_files)

        log_opts: list[str] | None = None
        scopes = []
        if req.mode in ("dir", "both"):
            scopes.append("working-tree")
        if req.mode in ("git", "both"):
            git = resolve_executable(settings.git_path, ErrorCode.GIT_NOT_FOUND)
            top = git_toplevel(git, req.target)
            if top is None:
                raise SecretSentinelError(ErrorCode.UNSUPPORTED_REPO)
            if top != req.target:
                raise SecretSentinelError(ErrorCode.UNSUPPORTED_REPO, "Git history scans require the repository root.")
            outcome.commit_sha = git_head(git, req.target)
            if outcome.commit_sha is None:
                raise SecretSentinelError(ErrorCode.UNSUPPORTED_REPO, "Repository has no commits.")
            if req.since_ref:
                base = git_resolve_commit(git, req.target, req.since_ref)
                log_opts = _GIT_SAFE_LOG_OPTS + [f"{base}..{outcome.commit_sha}"]
                scopes.append(f"commits:{base[:12]}..{outcome.commit_sha[:12]}")
            else:
                log_opts = _GIT_SAFE_LOG_OPTS + ["--full-history", "--all"]
                scopes.append("full-history")
        elif req.mode == "staged":
            # Only what `git commit` would record now (the index), for pre-commit hooks.
            git = resolve_executable(settings.git_path, ErrorCode.GIT_NOT_FOUND)
            top = git_toplevel(git, req.target)
            if top is None:
                raise SecretSentinelError(ErrorCode.UNSUPPORTED_REPO)
            if top != req.target:
                raise SecretSentinelError(ErrorCode.UNSUPPORTED_REPO, "Staged scans require the repository root.")
            outcome.commit_sha = git_head(git, req.target)  # None before the first commit
            scopes.append("staged-changes")
        elif req.mode == "dir" and settings.git_path:
            try:
                git = resolve_executable(settings.git_path, ErrorCode.GIT_NOT_FOUND)
                if git_toplevel(git, req.target) == req.target:
                    outcome.commit_sha = git_head(git, req.target)
            except SecretSentinelError:
                pass
        outcome.scope = "+".join(scopes)

        workdir = Path(tempfile.mkdtemp(prefix="secretsentinel-"))
        try:
            os.chmod(workdir, 0o700)
            ignore_dir = workdir / "no-ignore"
            ignore_dir.mkdir()
            config_path = workdir / "effective-config.toml"
            # write_bytes, not write_text: text mode on Windows would turn "\n" into
            # "\r\n" again, and Gitleaks rejects the resulting "\r\r\n" config.
            config_path.write_bytes(ruleset.effective_config(req.policy.exclude_paths).encode("utf-8"))
            os.chmod(config_path, 0o600)
            findings: list[SafeFinding] = []
            if req.mode == "staged":
                passes = [("git", None, STAGED_FLAGS)]
            else:
                passes = [(m, log_opts if m == "git" else None, None) for m in ("dir", "git") if req.mode in (m, "both")]
            for mode, opts, extra in passes:
                report_path = workdir / f"report-{mode}.json"
                cmd = build_gitleaks_command(
                    gitleaks, mode, config_path, report_path, ignore_dir, req.max_file_mb, opts, extra,
                )
                rc = _run_gitleaks(cmd, req.target, workdir, deadline, req.cancel_event)
                if rc not in (0, LEAK_EXIT_CODE):
                    raise SecretSentinelError(_classify_failure(workdir))
                records = _read_report(report_path, rc)
                safe, stats = sanitize_report(records, str(req.target), mode, stats)
                del records
                findings.extend(safe)
                try:
                    report_path.unlink()
                except OSError:
                    pass
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        findings.extend(_ignore_file_findings(req.target))
        findings = [f for f in findings if not is_excluded(f.relative_path, req.policy.exclude_paths)]
        findings = deduplicate(classify_all(findings, ruleset))
        outcome.findings = findings
        outcome.dropped_fields = stats.dropped_fields
        if stats.dropped_fields:
            outcome.warnings.append(f"sanitizer dropped {stats.dropped_fields} unexpected report field(s)")
        if stats.redaction_failures:
            outcome.warnings.append("scanner output was not redacted; raw values were discarded")
        outcome.status = "completed"
    except SecretSentinelError as exc:
        outcome.findings = []
        outcome.error_code = exc.code.value
        outcome.status = "cancelled" if exc.code == ErrorCode.SCAN_CANCELLED else "failed"
    except Exception:  # noqa: BLE001 - never leak exception text; fail closed
        outcome.findings = []
        outcome.error_code = ErrorCode.INTERNAL_ERROR.value
        outcome.status = "failed"
    finally:
        outcome.finished_at = _utcnow()

    fail_on = req.fail_on
    evaluate(outcome, fail_on, list(req.policy.suppressions) + list(req.extra_suppressions))
    log_event(
        _LOGGING_LEVEL_INFO if outcome.status == "completed" else _LOGGING_LEVEL_WARN,
        "scan.finished",
        mode=outcome.mode,
        status=outcome.status,
        policy_result=outcome.policy_result,
        error_code=outcome.error_code,
        duration_ms=int((time.monotonic() - started) * 1000),
        total_findings=outcome.total_findings,
        blocking_findings=outcome.blocking_findings,
        dropped_fields=outcome.dropped_fields,
        scanner_version=outcome.scanner_version,
    )
    return outcome
