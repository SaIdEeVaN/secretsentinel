"""Mandatory sanitizer for raw Gitleaks report records.

Deny by default:

* Only keys in ``SAFE_KEYS`` are ever read into the safe object. The result is
  built field by field; the raw record is never serialized.
* Keys in ``SENSITIVE_KEYS`` (Secret, Match, Line, Message, Author, Email, ...)
  are read only to cross-check that no safe field accidentally contains them,
  then discarded.
* Any other key is an unexpected field: it is dropped and counted, never
  copied (test T10).
* Every safe value is type-checked and normalized; anything malformed fails
  the whole scan with SANITIZATION_FAILED rather than being passed through.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from ..core.errors import ErrorCode, SecretSentinelError
from ..core.security import is_commit_sha, safe_text
from .types import SafeFinding

SAFE_KEYS = frozenset(
    {"RuleID", "File", "SymlinkFile", "StartLine", "EndLine", "StartColumn", "EndColumn", "Commit", "Entropy", "Tags"}
)
SENSITIVE_KEYS = frozenset(
    {
        "Secret",
        "Match",
        "Line",
        "Message",
        "Author",
        "Email",
        "Date",
        "Fingerprint",
        "Link",
        "Description",
        "Fragment",
    }
)
_REDACTION_MARKERS = {"", "REDACTED"}
_RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}$")
_TAG_RE = re.compile(r"^[A-Za-z0-9:_.-]{1,40}$")
OUTSIDE_ROOT = "<outside-scan-root>"
REDACTED_PATH = "<path-redacted>"
MAX_LINE = 10_000_000


@dataclass
class SanitizeStats:
    records: int = 0
    dropped_fields: int = 0
    redaction_failures: int = 0


def _int_field(record: dict, key: str) -> int:
    value = record.get(key, 0)
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > MAX_LINE:
        raise SecretSentinelError(ErrorCode.SANITIZATION_FAILED)
    return value


def normalize_path(raw: Any, scan_root: str | None) -> str:
    """Return a repository-relative, forward-slash path with no control characters."""
    if not isinstance(raw, str):
        raise SecretSentinelError(ErrorCode.SANITIZATION_FAILED)
    if raw == "":
        return ""
    text = raw.replace("\\", "/")
    is_abs = PurePosixPath(text).is_absolute() or PureWindowsPath(raw).is_absolute()
    if is_abs:
        if not scan_root:
            return OUTSIDE_ROOT
        root = scan_root.replace("\\", "/").rstrip("/")
        cmp_text, cmp_root = (text.lower(), root.lower()) if os.name == "nt" else (text, root)
        if cmp_text == cmp_root:
            text = ""
        elif cmp_text.startswith(cmp_root + "/"):
            text = text[len(root) + 1 :]
        else:
            return OUTSIDE_ROOT
    while text.startswith("./"):
        text = text[2:]
    parts = [p for p in text.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return OUTSIDE_ROOT
    return safe_text("/".join(parts), max_len=1024)


def _sensitive_values(record: dict) -> list[str]:
    """Raw values to cross-check, present only when redaction did NOT happen."""
    secret = record.get("Secret")
    if not isinstance(secret, str) or secret in _REDACTION_MARKERS:
        return []
    values = [secret] if len(secret) >= 4 else []
    for key in ("Match", "Line"):
        value = record.get(key)
        if isinstance(value, str) and len(value) >= 6:
            values.append(value)
    return values


def sanitize_record(record: Any, scan_root: str | None, source: str, stats: SanitizeStats) -> SafeFinding:
    if not isinstance(record, dict):
        raise SecretSentinelError(ErrorCode.SANITIZATION_FAILED)
    stats.records += 1
    for key in record:
        if key not in SAFE_KEYS and key not in SENSITIVE_KEYS:
            stats.dropped_fields += 1

    rule_id = record.get("RuleID")
    if not isinstance(rule_id, str) or not _RULE_ID_RE.match(rule_id):
        raise SecretSentinelError(ErrorCode.SANITIZATION_FAILED)

    path = normalize_path(record.get("File", ""), scan_root)
    commit = record.get("Commit") or None
    if commit is not None:
        if not isinstance(commit, str):
            raise SecretSentinelError(ErrorCode.SANITIZATION_FAILED)
        commit = commit.lower()
        if not is_commit_sha(commit):
            commit = None

    entropy_raw = record.get("Entropy")
    entropy: float | None = None
    if isinstance(entropy_raw, (int, float)) and not isinstance(entropy_raw, bool):
        if math.isfinite(entropy_raw) and 0 <= entropy_raw <= 64:
            entropy = round(float(entropy_raw), 2)

    tags_raw = record.get("Tags") or []
    tags: tuple[str, ...] = ()
    if isinstance(tags_raw, list):
        tags = tuple(t for t in tags_raw if isinstance(t, str) and _TAG_RE.match(t))[:16]

    finding = SafeFinding(
        rule_id=rule_id,
        relative_path=path,
        start_line=_int_field(record, "StartLine"),
        end_line=_int_field(record, "EndLine"),
        start_column=_int_field(record, "StartColumn"),
        end_column=_int_field(record, "EndColumn"),
        commit_sha=commit,
        entropy=entropy,
        tags=tags,
        sources=(source,),
    )

    # Defense in depth: if redaction did not happen (e.g. a misconfigured or
    # tampered scanner), make sure no safe field echoes the raw value. A file
    # literally named after a secret gets its path replaced.
    sensitive = _sensitive_values(record)
    if sensitive:
        stats.redaction_failures += 1
        for value in sensitive:
            if len(value) >= 4 and value in finding.relative_path:
                finding.relative_path = REDACTED_PATH
    assert_no_secret_material(finding, sensitive)
    return finding


def assert_no_secret_material(finding: SafeFinding, sensitive_values: list[str]) -> None:
    if not sensitive_values:
        return
    blob = repr(finding.to_safe_dict())
    for value in sensitive_values:
        if len(value) >= 4 and value in blob:
            raise SecretSentinelError(ErrorCode.SANITIZATION_FAILED)


def sanitize_report(
    records: Any, scan_root: str | None, source: str, stats: SanitizeStats | None = None
) -> tuple[list[SafeFinding], SanitizeStats]:
    stats = stats or SanitizeStats()
    if not isinstance(records, list):
        raise SecretSentinelError(ErrorCode.REPORT_PARSE_FAILED)
    return [sanitize_record(r, scan_root, source, stats) for r in records], stats
