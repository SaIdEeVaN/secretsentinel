"""Locate SecretSentinel's own data directories (rules, frontend build).

These are resolved relative to the *SecretSentinel installation*, never
relative to a scanned repository, so a scanned repository cannot swap in its
own ruleset or configuration.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent


def _search_upwards(relative: str, max_levels: int = 4) -> Path | None:
    current = _PACKAGE_DIR
    for _ in range(max_levels):
        candidate = current / relative
        if candidate.exists():
            return candidate
        if current.parent == current:
            break
        current = current.parent
    return None


@lru_cache(maxsize=None)
def find_rules_dir() -> Path:
    override = os.environ.get("SECRETSENTINEL_RULES_DIR")
    if override:
        return Path(override).expanduser().resolve()
    found = _search_upwards("rules/web3_rules.toml")
    if found is None:
        raise FileNotFoundError(
            "SecretSentinel rules directory not found; set SECRETSENTINEL_RULES_DIR"
        )
    return found.parent


def find_frontend_dist() -> Path | None:
    override = os.environ.get("SECRETSENTINEL_FRONTEND_DIST")
    if override:
        path = Path(override).expanduser().resolve()
        return path if (path / "index.html").exists() else None
    found = _search_upwards("frontend/dist/index.html")
    return found.parent if found else None


def project_root() -> Path | None:
    """Root of a source checkout (directory containing ``rules/``), if any."""
    try:
        return find_rules_dir().parent
    except FileNotFoundError:
        return None
