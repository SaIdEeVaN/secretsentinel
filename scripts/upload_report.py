#!/usr/bin/env python3
"""Upload a SANITIZED SecretSentinel JSON report to a hosted dashboard.

    SECRETSENTINEL_DASHBOARD_URL=https://<name>.onrender.com \
    SECRETSENTINEL_INGEST_TOKEN=... \
    python scripts/upload_report.py secretsentinel-report.json

* The report must be the `secretsentinel-report/v1` JSON written by
  `secretsentinel check|scan --format json`; it contains rule IDs and
  locations only, never secret values. The server rejects anything else.
* The token is read from the environment and is never printed.
* Free hosting tiers sleep when idle, so connection errors and 502/503/504
  responses are retried with back-off while the service wakes up.
* Standard library only, so it runs in the minimal CI environment.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

SCHEMA = "secretsentinel-report/v1"
INGEST_PATH = "/api/v1/ingest/scan-summary"
RETRY_STATUSES = {502, 503, 504}


def _fail(message: str) -> int:
    print(f"upload_report: {message}", file=sys.stderr)
    return 1


def build_url(base: str) -> str:
    parsed = urlparse(base.strip())
    local = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise ValueError("dashboard URL must use https:// (http:// is allowed only for localhost)")
    if not parsed.hostname:
        raise ValueError("dashboard URL has no host")
    return f"{parsed.scheme}://{parsed.netloc}{INGEST_PATH}"


def load_report(path: str, repository: str | None) -> dict:
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    if not isinstance(report, dict) or report.get("schema") != SCHEMA:
        raise ValueError(f"not a {SCHEMA} report")
    if repository:
        report["repository_name"] = repository[:200]
    return report


def post(url: str, token: str, report: dict, attempts: int, timeout: int, wait: float) -> tuple[int, dict]:
    body = json.dumps(report).encode("utf-8")
    last_error = "no attempt made"
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}", "User-Agent": "secretsentinel-upload"},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - scheme validated
                return response.status, json.loads(response.read(65536) or b"{}")
        except urllib.error.HTTPError as exc:
            if exc.code not in RETRY_STATUSES:
                try:
                    payload = json.loads(exc.read(65536) or b"{}")
                except ValueError:
                    payload = {}
                return exc.code, payload
            last_error = f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = type(exc).__name__
        if attempt < attempts:
            delay = wait * attempt
            print(f"upload_report: dashboard not ready ({last_error}); retrying in {delay:.0f}s "
                  f"(attempt {attempt}/{attempts})", file=sys.stderr)
            time.sleep(delay)
    return 0, {"error": {"code": "UNREACHABLE", "message": f"gave up after {attempts} attempts ({last_error})"}}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("report", help="path to the secretsentinel-report/v1 JSON file")
    ap.add_argument("--url", default=os.environ.get("SECRETSENTINEL_DASHBOARD_URL", ""), help="dashboard base URL")
    ap.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"), help="owner/name shown in the dashboard")
    ap.add_argument("--attempts", type=int, default=6)
    ap.add_argument("--timeout", type=int, default=90)
    ap.add_argument("--wait", type=float, default=15.0, help="base back-off in seconds")
    args = ap.parse_args(argv)

    token = os.environ.get("SECRETSENTINEL_INGEST_TOKEN", "")
    if not token:
        return _fail("SECRETSENTINEL_INGEST_TOKEN is not set")
    if not args.url:
        return _fail("dashboard URL missing (set SECRETSENTINEL_DASHBOARD_URL or pass --url)")
    try:
        url = build_url(args.url)
        report = load_report(args.report, args.repository)
    except (OSError, ValueError) as exc:
        return _fail(str(exc))

    status, payload = post(url, token, report, args.attempts, args.timeout, args.wait)
    host = urlparse(url).netloc
    if status == 201:
        scan = report.get("scan", {})
        print(
            f"Uploaded to {host}: scan {payload.get('scan_id')} - status {scan.get('status')}, "
            f"policy {scan.get('policy_result')}, {scan.get('blocking_findings', 0)} blocking of "
            f"{scan.get('total_findings', 0)} finding(s)."
        )
        return 0
    error = payload.get("error", {}) if isinstance(payload, dict) else {}
    hint = {401: " Check SECRETSENTINEL_INGEST_TOKEN matches the dashboard's INGEST_TOKEN.",
            404: " Uploads may be disabled on the dashboard (INGEST_TOKEN not set)."}.get(status, "")
    return _fail(f"upload to {host} failed: HTTP {status} {error.get('code', '')} {str(error.get('message', '')).rstrip('.')}.{hint}")


if __name__ == "__main__":
    sys.exit(main())
