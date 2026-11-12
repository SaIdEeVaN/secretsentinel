#!/usr/bin/env python3
"""Warn before a GitHub token stored as a secret expires.

    TOKEN=... python scripts/token_expiry.py --warn-days 14 --fail-days 7

GitHub returns a fine-grained token's expiry in the
``GitHub-Authentication-Token-Expiration`` response header. This script makes
one request to ``/rate_limit`` (it costs no rate limit) and:

* exits 0 if the token is unset, does not expire, or has more than
  ``--warn-days`` left;
* prints a ``::warning`` annotation when ``--warn-days`` or fewer are left;
* prints a ``::error`` annotation and exits 1 when ``--fail-days`` or fewer
  are left, or when GitHub no longer accepts the token. A failed run makes
  GitHub email the workflow's owner.

The token is only sent to GitHub and is never printed. Only the expiry date
and day count are, which is safe in public logs. Standard library only.
"""

from __future__ import annotations

import argparse
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

HEADER = "GitHub-Authentication-Token-Expiration"
FORMATS = ("%Y-%m-%d %H:%M:%S %Z", "%Y-%m-%d %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z")


def parse_expiry(value: str) -> datetime | None:
    value = value.strip()
    for fmt in FORMATS:
        try:
            parsed = datetime.strptime(value, fmt)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def days_left(expiry: datetime, now: datetime | None = None) -> float:
    now = now or datetime.now(timezone.utc)
    return (expiry - now).total_seconds() / 86400


def fetch_expiry(token: str, api: str, timeout: int = 20) -> tuple[int, str | None]:
    """Return (HTTP status, expiry header or None)."""
    request = urllib.request.Request(
        f"{api.rstrip('/')}/rate_limit",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "User-Agent": "secretsentinel-token-check"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https API URL
            return response.status, response.headers.get(HEADER)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get(HEADER) if exc.headers else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--env-var", default="TOKEN", help="environment variable holding the token (default: TOKEN)")
    ap.add_argument("--name", default="SECRETSENTINEL_REPO_READ_TOKEN", help="name shown in messages")
    ap.add_argument("--warn-days", type=float, default=14)
    ap.add_argument("--fail-days", type=float, default=7)
    ap.add_argument("--api", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    args = ap.parse_args(argv)

    token = os.environ.get(args.env_var, "")
    if not token:
        print(f"{args.name} is not set; nothing to check.")
        return 0
    try:
        status, header = fetch_expiry(token, args.api)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"::warning title=Token check skipped::Could not reach GitHub to check {args.name} ({type(exc).__name__}).")
        return 0
    if status == 401:
        print(f"::error title={args.name} rejected::GitHub no longer accepts {args.name} (expired or revoked). "
              "Create a new token with the same settings and update the secret (docs/HOSTING.md).")
        return 1
    if not header:
        print(f"{args.name}: GitHub reports no expiry date for this token.")
        return 0
    expiry = parse_expiry(header)
    if expiry is None:
        print(f"::warning title=Token check skipped::Unrecognised expiry format for {args.name}.")
        return 0
    left = days_left(expiry)
    when = expiry.strftime("%Y-%m-%d")
    if left <= args.fail_days:
        print(f"::error title={args.name} expires soon::{args.name} expires on {when} ({max(left, 0):.0f} day(s) left). "
              "Create a new token with the same settings and update the secret (docs/HOSTING.md).")
        return 1
    if left <= args.warn_days:
        print(f"::warning title={args.name} expires soon::{args.name} expires on {when} ({left:.0f} day(s) left).")
        return 0
    print(f"{args.name} expires on {when} ({left:.0f} day(s) left).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
