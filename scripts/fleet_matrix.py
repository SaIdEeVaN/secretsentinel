#!/usr/bin/env python3
"""Turn the dashboard repository list into a GitHub Actions matrix.

    python scripts/fleet_matrix.py .github/dashboard-repos.txt

Prints a JSON array of "owner/name" strings. Every entry is validated, so a
malformed or hostile line fails the run instead of reaching a later step.
Standard library only.
"""

from __future__ import annotations

import json
import re
import sys

# GitHub's own limits: owner up to 39 chars (alphanumerics and hyphens),
# repository up to 100 chars (alphanumerics, hyphen, underscore, dot).
REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
MAX_REPOS = 100


def parse(text: str) -> list[str]:
    repos: list[str] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        name = line.rsplit("/", 1)[-1]
        if not REPO_RE.match(line) or name in {".", ".."}:
            raise ValueError(f"line {number}: not a valid owner/name repository")
        if line.lower() not in {r.lower() for r in repos}:
            repos.append(line)
    if len(repos) > MAX_REPOS:
        raise ValueError(f"too many repositories ({len(repos)} > {MAX_REPOS})")
    return repos


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: fleet_matrix.py <list-file>", file=sys.stderr)
        return 2
    try:
        with open(args[0], encoding="utf-8") as fh:
            repos = parse(fh.read())
    except (OSError, ValueError) as exc:
        print(f"fleet_matrix: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(repos))
    return 0


if __name__ == "__main__":
    sys.exit(main())
