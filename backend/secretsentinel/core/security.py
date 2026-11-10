"""Path, reference and text safety helpers.

Trust boundary: scanned repositories are hostile DATA. File names, Git refs
and every byte of content are treated as untrusted. Nothing in this module
executes repository content.
"""

from __future__ import annotations

import os
import re
import unicodedata
from pathlib import Path
from typing import Iterable

from .errors import ErrorCode, SecretSentinelError

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/~^-]{0,199}$")


def canonicalize_existing_dir(raw: str | os.PathLike[str]) -> Path:
    """Resolve a user-supplied directory path (following symlinks) or raise."""
    text = os.fspath(raw)
    if not text or "\x00" in text or len(text) > 4096:
        raise SecretSentinelError(ErrorCode.PATH_NOT_FOUND)
    try:
        resolved = Path(text).expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        raise SecretSentinelError(ErrorCode.PATH_NOT_FOUND) from None
    if not resolved.is_dir():
        raise SecretSentinelError(ErrorCode.PATH_NOT_FOUND)
    return resolved


def ensure_within_allowed_roots(path: Path, roots: Iterable[Path]) -> Path:
    """Ensure an already-canonical path lies inside one of the allowed roots.

    ``path`` must come from :func:`canonicalize_existing_dir`, so symlinks have
    been resolved and a link pointing outside the root is rejected here.
    """
    resolved_roots = []
    for root in roots:
        try:
            resolved_roots.append(Path(root).resolve(strict=True))
        except (OSError, RuntimeError):
            continue
    for root in resolved_roots:
        if path == root or path.is_relative_to(root):
            return path
    raise SecretSentinelError(ErrorCode.PATH_NOT_ALLOWED)


def check_repo_size(path: Path, max_mb: int, max_files: int) -> int:
    """Walk the target (without following symlinks) and enforce size limits.

    Returns the total size in bytes. Raises REPO_TOO_LARGE early once a limit
    is exceeded, so a huge tree cannot keep the walker busy.
    """
    limit = max_mb * 1024 * 1024
    total = 0
    count = 0
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        for name in filenames:
            count += 1
            if count > max_files:
                raise SecretSentinelError(ErrorCode.REPO_TOO_LARGE)
            try:
                st = os.lstat(os.path.join(dirpath, name))
            except OSError:
                continue
            total += st.st_size
            if total > limit:
                raise SecretSentinelError(ErrorCode.REPO_TOO_LARGE)
    return total


def is_commit_sha(value: str | None) -> bool:
    return bool(value) and bool(_SHA_RE.match(value))


def validate_ref_syntax(ref: str) -> str:
    """Syntactic validation of a Git ref before it is resolved to a SHA.

    Rejects whitespace (Gitleaks splits --log-opts on spaces), leading dashes
    (option injection into ``git log``) and range syntax.
    """
    if (
        not ref
        or not _REF_RE.match(ref)
        or ".." in ref
        or "//" in ref
        or ref.endswith("/")
        or ref.endswith(".lock")
    ):
        raise SecretSentinelError(ErrorCode.INVALID_GIT_REF)
    return ref


def safe_text(value: object, max_len: int = 512) -> str:
    """Strip control characters and truncate. For metadata, never for secrets."""
    text = unicodedata.normalize("NFC", str(value))
    text = _CONTROL_RE.sub("?", text)
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text


def is_loopback_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


_GLOB_SPECIAL = set(".^$*+?()[]{}|\\")


def glob_to_regex(pattern: str, descendants: bool = False) -> str:
    """Translate a path glob into a regex valid in BOTH Python ``re`` and Go RE2.

    Supported syntax: ``**`` (any depth), ``*`` (within a segment), ``?``.
    A pattern without ``/`` matches at any depth (``node_modules`` ==
    ``**/node_modules``); a trailing ``/**`` matches everything below.
    Separators match both ``/`` and ``\\`` so Windows paths work. With
    ``descendants=True`` anything below a matching directory also matches
    (exclusion semantics).
    """
    p = pattern.strip().replace("\\", "/")
    if not p:
        raise ValueError("empty glob")
    if p.startswith("./"):
        p = p[2:]
    if "/" not in p.rstrip("/"):
        p = "**/" + p
    if p.endswith("/"):
        p = p + "**"
    sep = r"[/\\]"
    seg = r"[^/\\]"
    out: list[str] = []
    i = 0
    while i < len(p):
        if p.startswith("**/", i):
            out.append(f"(?:{seg}*{sep})*")
            i += 3
        elif p.startswith("/**", i) and i + 3 == len(p):
            out.append(f"(?:{sep}.*)?")
            i += 3
        elif p.startswith("**", i):
            out.append(".*")
            i += 2
        elif p[i] == "*":
            out.append(f"{seg}*")
            i += 1
        elif p[i] == "?":
            out.append(seg)
            i += 1
        elif p[i] == "/":
            out.append(sep)
            i += 1
        elif p[i] in _GLOB_SPECIAL:
            out.append("\\" + p[i])
            i += 1
        else:
            out.append(p[i])
            i += 1
    tail = rf"(?:{sep}.*)?$" if descendants else "$"
    return r"^(?:\./)?" + "".join(out) + tail


def glob_match(pattern: str, path: str, descendants: bool = False) -> bool:
    return re.match(glob_to_regex(pattern, descendants), path) is not None
