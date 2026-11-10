"""Blocking policy, reviewed suppressions and baselines.

Rules enforced here (FIND-06, FIND-07, CI-07, T11):

* A suppression only applies if it names a rule, a path scope, a reason
  (>= 10 characters), a reviewer and an expiry date no more than
  ``MAX_SUPPRESSION_DAYS`` in the future. Anything less is ignored with a
  warning, and the finding keeps blocking.
* Expired suppressions stop applying automatically.
* Baseline entries are suppressions that share one reason/reviewer/expiry.
  Baselined findings are still reported (status ``suppressed``), only not
  blocking.
* Policy is evaluated separately from scan execution: a scan that did not
  complete is never ``pass`` (invariant S3).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from ..core.config import FAIL_ON_LEVELS
from ..core.errors import ErrorCode, SecretSentinelError
from ..core.security import glob_match, glob_to_regex, is_commit_sha
from .types import SEVERITY_ORDER, SafeFinding, ScanOutcome

POLICY_FILENAMES = (".secretsentinel.yml", ".secretsentinel.yaml")
BASELINE_SCHEMA = "secretsentinel-baseline/v1"
MAX_SUPPRESSION_DAYS = 366
MIN_REASON_LEN = 10
_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
_RULE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}$")


def _parse_date(value: Any) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip()[:10])
        except ValueError:
            return None
    return None


@dataclass
class Suppression:
    id: str
    rule_id: str | None
    path: str | None = None
    line: int | None = None
    commit_sha: str | None = None
    fingerprint: str | None = None
    reason: str | None = None
    reviewer: str | None = None
    created: date | None = None
    expires: date | None = None
    origin: str = "policy"  # policy | baseline | dashboard
    exact_path: bool = False

    def problem(self, today: date) -> str | None:
        """Return a constant problem code if the suppression must not apply."""
        if not self.rule_id or not _RULE_RE.match(self.rule_id):
            return "missing-or-invalid-rule"
        if not (self.path or self.fingerprint):
            return "missing-scope"
        if not self.reason or len(self.reason.strip()) < MIN_REASON_LEN:
            return "missing-reason"
        if not self.reviewer or not self.reviewer.strip():
            return "missing-reviewer"
        if self.expires is None:
            return "missing-expiry"
        if self.expires < today:
            return "expired"
        if self.expires > today + timedelta(days=MAX_SUPPRESSION_DAYS):
            return "expiry-too-far"
        if self.path and not self.exact_path:
            try:
                glob_to_regex(self.path)
            except ValueError:
                return "invalid-path"
        return None

    def matches(self, f: SafeFinding) -> bool:
        if f.rule_id != self.rule_id:
            return False
        if self.fingerprint and self.fingerprint != f.fingerprint:
            return False
        if self.path:
            if self.exact_path:
                if self.path != f.relative_path:
                    return False
            elif not glob_match(self.path, f.relative_path):
                return False
        if self.commit_sha and f.commit_sha and self.commit_sha != f.commit_sha:
            return False
        if self.line is not None and self.line != f.start_line:
            # A commit match is a stronger identity than a (shifting) line number.
            if not (self.commit_sha and f.commit_sha == self.commit_sha):
                return False
        return True

    def as_safe_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "path": self.path,
            "line": self.line,
            "commit_sha": self.commit_sha,
            "fingerprint": self.fingerprint,
            "reviewer": self.reviewer,
            "expires": self.expires.isoformat() if self.expires else None,
            "origin": self.origin,
        }


@dataclass
class Policy:
    fail_on: str | None = None
    exclude_paths: tuple[str, ...] = ()
    suppressions: list[Suppression] = field(default_factory=list)
    source: str | None = None

    @classmethod
    def empty(cls) -> "Policy":
        return cls()

    @property
    def digest(self) -> str:
        payload = {
            "fail_on": self.fail_on,
            "exclude_paths": list(self.exclude_paths),
            "suppressions": [s.as_safe_dict() for s in self.suppressions],
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def _suppression_from_dict(raw: dict, origin: str, defaults: dict | None = None) -> Suppression:
    d = {**(defaults or {}), **raw}
    sid = str(d.get("id") or "")
    if not _ID_RE.match(sid):
        raise SecretSentinelError(ErrorCode.INVALID_POLICY, "Each suppression needs a short id.")
    line = d.get("line", d.get("start_line"))
    if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 0):
        raise SecretSentinelError(ErrorCode.INVALID_POLICY, "Suppression line must be an integer.")
    commit = d.get("commit") or d.get("commit_sha")
    if commit is not None:
        commit = str(commit).lower()
        if not is_commit_sha(commit):
            raise SecretSentinelError(ErrorCode.INVALID_POLICY, "Suppression commit must be a full SHA.")
    path = d.get("path") or d.get("relative_path")
    return Suppression(
        id=sid,
        rule_id=str(d["rule_id"]) if d.get("rule_id") else None,
        path=str(path) if path else None,
        line=line,
        commit_sha=commit,
        fingerprint=str(d["fingerprint"]) if d.get("fingerprint") else None,
        reason=str(d["reason"]) if d.get("reason") else None,
        reviewer=str(d["reviewer"]) if d.get("reviewer") else None,
        created=_parse_date(d.get("created")),
        expires=_parse_date(d.get("expires")),
        origin=origin,
    )


def load_baseline(path: Path) -> list[Suppression]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise SecretSentinelError(ErrorCode.INVALID_POLICY, "Baseline file is unreadable.") from None
    if not isinstance(data, dict) or data.get("schema") != BASELINE_SCHEMA:
        raise SecretSentinelError(ErrorCode.INVALID_POLICY, "Unsupported baseline schema.")
    defaults = {
        "reason": data.get("reason"),
        "reviewer": data.get("reviewer"),
        "created": data.get("created"),
        "expires": data.get("expires"),
    }
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise SecretSentinelError(ErrorCode.INVALID_POLICY, "Baseline entries must be a list.")
    result = []
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise SecretSentinelError(ErrorCode.INVALID_POLICY, "Baseline entry must be an object.")
        safe = {k: entry.get(k) for k in ("rule_id", "relative_path", "start_line", "commit_sha")}
        safe["id"] = f"baseline-{idx + 1}"
        sup = _suppression_from_dict(safe, "baseline", defaults)
        sup.exact_path = True
        result.append(sup)
    return result


def load_policy(path: Path) -> Policy:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError, UnicodeDecodeError):
        raise SecretSentinelError(ErrorCode.INVALID_POLICY, "Policy file is unreadable.") from None
    if not isinstance(raw, dict):
        raise SecretSentinelError(ErrorCode.INVALID_POLICY)
    unknown = set(raw) - {"version", "fail_on", "exclude_paths", "suppressions", "baseline"}
    if unknown:
        raise SecretSentinelError(ErrorCode.INVALID_POLICY, "Policy file has unknown top-level keys.")
    if raw.get("version", 1) != 1:
        raise SecretSentinelError(ErrorCode.INVALID_POLICY, "Unsupported policy version.")
    fail_on = raw.get("fail_on")
    if fail_on is not None and fail_on not in FAIL_ON_LEVELS:
        raise SecretSentinelError(ErrorCode.INVALID_POLICY, "fail_on must be critical|high|medium|low|none.")
    excludes = raw.get("exclude_paths") or []
    if not isinstance(excludes, list) or not all(isinstance(e, str) and e.strip() for e in excludes):
        raise SecretSentinelError(ErrorCode.INVALID_POLICY, "exclude_paths must be a list of globs.")
    for e in excludes:
        try:
            glob_to_regex(e)
        except ValueError:
            raise SecretSentinelError(ErrorCode.INVALID_POLICY, "Invalid exclude glob.") from None
    suppressions_raw = raw.get("suppressions") or []
    if not isinstance(suppressions_raw, list):
        raise SecretSentinelError(ErrorCode.INVALID_POLICY, "suppressions must be a list.")
    suppressions = []
    for s in suppressions_raw:
        if not isinstance(s, dict):
            raise SecretSentinelError(ErrorCode.INVALID_POLICY, "Each suppression must be a mapping.")
        suppressions.append(_suppression_from_dict(s, "policy"))
    ids = [s.id for s in suppressions]
    if len(ids) != len(set(ids)):
        raise SecretSentinelError(ErrorCode.INVALID_POLICY, "Suppression ids must be unique.")
    baseline = raw.get("baseline")
    if baseline:
        bpath = (path.parent / str(baseline)).resolve()
        if not bpath.is_relative_to(path.parent.resolve()):
            raise SecretSentinelError(ErrorCode.INVALID_POLICY, "Baseline must live next to the policy file.")
        suppressions.extend(load_baseline(bpath))
    return Policy(
        fail_on=fail_on,
        exclude_paths=tuple(e.strip() for e in excludes),
        suppressions=suppressions,
        source=path.name,
    )


def discover_policy(target: Path, explicit: Path | None = None) -> Policy:
    if explicit is not None:
        if not explicit.is_file():
            raise SecretSentinelError(ErrorCode.INVALID_POLICY, "Policy file not found.")
        return load_policy(explicit)
    for name in POLICY_FILENAMES:
        candidate = target / name
        if candidate.is_file() and not candidate.is_symlink():
            return load_policy(candidate)
    return Policy.empty()


def is_excluded(path: str, globs: tuple[str, ...]) -> bool:
    return any(glob_match(g, path, descendants=True) for g in globs)


def evaluate(outcome: ScanOutcome, fail_on: str, suppressions: list[Suppression], today: date | None = None) -> None:
    """Apply suppressions and the blocking threshold; set ``policy_result``."""
    today = today or datetime.now(timezone.utc).date()
    threshold = SEVERITY_ORDER.get(fail_on, SEVERITY_ORDER["high"]) if fail_on != "none" else 99
    active: list[Suppression] = []
    for s in suppressions:
        problem = s.problem(today)
        if problem:
            outcome.warnings.append(f"suppression {s.id} ignored: {problem}")
        else:
            active.append(s)
    for f in outcome.findings:
        match = next((s for s in active if s.matches(f)), None)
        if match is not None:
            f.status = "suppressed"
            f.suppression_id = match.id
        f.blocking = f.status != "suppressed" and SEVERITY_ORDER.get(f.severity, 0) >= threshold
    outcome.fail_on = fail_on
    if outcome.status != "completed":
        outcome.policy_result = "not_evaluated"
    else:
        outcome.policy_result = "fail" if outcome.blocking_findings else "pass"


def build_baseline(findings: list[SafeFinding], reason: str, reviewer: str, expires: date, ruleset_digest: str | None) -> dict:
    today = datetime.now(timezone.utc).date()
    probe = Suppression(id="probe", rule_id="probe", path="probe", reason=reason, reviewer=reviewer, expires=expires)
    problem = probe.problem(today)
    if problem:
        raise SecretSentinelError(ErrorCode.INVALID_POLICY, f"Baseline rejected: {problem}.")
    entries = [
        {
            "rule_id": f.rule_id,
            "relative_path": f.relative_path,
            "start_line": f.start_line,
            "commit_sha": f.commit_sha,
            "fingerprint": f.fingerprint,
        }
        for f in findings
    ]
    return {
        "schema": BASELINE_SCHEMA,
        "created": today.isoformat(),
        "expires": expires.isoformat(),
        "reviewer": reviewer,
        "reason": reason,
        "ruleset_digest": ruleset_digest,
        "note": "Contains only rule IDs and locations. No secret values. Review before committing.",
        "entries": entries,
    }
