#!/usr/bin/env python3
"""Fail if any synthetic fixture canary appears in the given files/directories.

Every synthetic fixture value (and distinctive 20-character prefixes/suffixes)
is a canary. Point this at CI logs, exported reports, step summaries or a
SQLite dump; it exits 1 and prints MASKED hits if anything leaked.

    PYTHONPATH=backend python scripts/check_no_raw_secrets.py out/ report.json
    PYTHONPATH=backend python scripts/check_no_raw_secrets.py --self-test

Never point it at the materialised fixture directory itself: those files contain
the canaries by design.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from secretsentinel.fixtures import all_canaries, find_leaks  # noqa: E402

MAX_BYTES = 64 * 1024 * 1024


def _read(path: Path) -> str:
    if path.suffix == ".db":
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            return "\n".join(con.iterdump())
        finally:
            con.close()
    return path.read_bytes()[:MAX_BYTES].decode("utf-8", "replace")


def scan_paths(paths: list[Path], canaries: set[str]) -> list[tuple[Path, list[str]]]:
    hits = []
    for root in paths:
        files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
        for f in files:
            leaks = find_leaks(_read(f), canaries)
            if leaks:
                hits.append((f, leaks))
    return hits


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="*", type=Path)
    ap.add_argument("--self-test", action="store_true", help="verify the detector flags a planted canary")
    args = ap.parse_args(argv)
    canaries = all_canaries()
    if args.self_test:
        sample = sorted(canaries)[0]
        ok = bool(find_leaks(f"x {sample} y", canaries)) and not find_leaks("clean text", canaries)
        print(f"self-test {'passed' if ok else 'FAILED'} ({len(canaries)} canaries loaded)")
        return 0 if ok else 1
    if not args.paths:
        ap.error("give at least one file or directory")
    hits = scan_paths(args.paths, canaries)
    for f, leaks in hits:
        print(f"LEAK in {f}: {', '.join(leaks)}")
    if hits:
        return 1
    print(f"OK: no synthetic secret canaries found ({len(canaries)} canaries checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
