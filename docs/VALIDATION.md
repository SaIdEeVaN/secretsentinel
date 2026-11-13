# Local MVP validation

Re-validated on 10 November 2026 after merging the `codex/environment-setup`
work into `main`, in a Linux x64 container (4 vCPU) with Python 3.13.18,
Node.js 22.23.4, npm 10.9.9, Gitleaks 8.30.1 (built from the v8.30.1 tag) and
the preinstalled Chromium. No live credentials, wallet connections, hosted
deployments or Sepolia calls were used.

| Check | Observed result |
|---|---|
| `cd backend && python -m pytest -q` (real Gitleaks) | 206 passed, 3 skipped (the `chain` interop tests, run separately below) |
| `pytest -m chain tests/test_chain_interop.py` against a local Hardhat node | 3 passed |
| `cd frontend && npm test` | 19 passed across 3 files |
| `cd frontend && npm run test:e2e` | Production build passed; 6 browser tests passed (desktop + 390 px phone); 30/30 with `--repeat-each 5` |
| `cd contracts && npx hardhat test` | 8 passing |
| `bash scripts/ci_gate_selftest.sh` in a PyYAML-only environment | All 12 gate checks passed (clean, fixtures in 4 formats, clean/leaking PR, bad policy, bad ref, missing scanner, no canaries, annotations) |
| `python scripts/check_no_raw_secrets.py --self-test` | Passed, 33 canaries loaded |
| `actionlint` 1.7.7 on all workflows, `git diff --check` | Passed |
| `secretsentinel check . --mode both` on this repository | Pass: no matching secrets detected in the scanned scope |
| `secretsentinel attest create → publish → verify --onchain` (local chain) | Attestation verified; a tampered bundle was rejected (exit 1) |

## Measured against PRD targets (synthetic data only)

| Target | Result |
|---|---|
| Synthetic detection ≥ 90% | 29/29 positive fixtures detected by the intended rule (100%) |
| False positives ≤ 10% | 0/12 benign fixtures produced any finding (0%) |
| Safe reporting | 0 canaries in CLI output, JSON/SARIF/CSV, GitHub annotations/summary, API responses, SQLite dumps, logs, browser responses/storage |
| CI correctness | Every leaking fixture run and the leaking simulated PR exited 1; errors exited 2/3 |
| Latency ≤ 30 s, < 1,000 files | 999 files / 6 commits / 5.5 MB: `dir` 1.3 s, `git` 1.3 s, `both` 2.4 s (including Python start-up) |

These figures describe a curated, versioned synthetic fixture set and one
benchmark machine. They are not claims about real-world detection rates or
performance.

## Behaviors exercised

- Real Gitleaks directory, Git-history and combined scans; history-only and
  uncommitted synthetic findings; benign fixtures; scanner errors, malformed
  reports, timeouts and cancellation; repo `.gitleaksignore`, `.gitleaks.toml`
  and inline `gitleaks:allow` bypass attempts.
- Safe persistence, path/symlink validation, filtering, audited triage, reviewed
  suppression (including restoring the blocking decision on deactivation),
  expiry rules, baselines and status carry-over between scans.
- JSON/CSV/SARIF downloads, including more findings than the API page limit,
  spreadsheet formula neutralization and rejection of incomplete/stale reviews.
- Desktop and phone browser flows against a real isolated backend: demo
  creation, combined scan, historic-key visibility, triage, downloads,
  blocked-to-clean rescans, retained historical findings, rejected paths and
  mobile navigation; absence of the planted value from browser data and SQLite.
- Security middleware: Host (DNS rebinding), Origin, content type, token auth,
  rate limiting and refusal to bind remotely without authentication.
- Optional attestations: canonicalisation, signing, tamper/untrusted-signer/
  wrong-chain rejection, and registration/verification against the deployed
  `ScanRegistry` on a local chain.

## Defects found and fixed during the merge

Both surfaced only on GitHub-hosted runners, not in local runs:

1. **Stale reads after writes (browser suite, Linux runner).** FastAPI runs a
   request-scoped `yield` dependency's teardown - where the SQLite session
   commits - only after the response has been sent, so a client reading
   immediately after a write could see old data. All routes now use
   `Depends(get_db, scope="function")` (FastAPI >= 0.121), which commits before
   responding; `test_db_sessions_commit_before_the_response_is_sent` guards
   every route (it flags 6 routes on the pre-fix code). The browser job passed
   on GitHub after the fix.
2. **Every real scan failed with `INVALID_CONFIG` on Windows.** Windows
   checkouts convert `rules/*.toml` to CRLF; writing the generated config in
   text mode turned that into `\r\r\n`, which Gitleaks rejects ("invalid
   character in comment", reproduced locally). The ruleset is now normalised to
   LF on load (so the ruleset digest is identical on every OS), the config is
   written as bytes, and `.gitattributes` keeps scanner inputs LF. Guarded by
   `test_crlf_checkout_has_same_digest_and_clean_config` and
   `test_scan_works_with_crlf_ruleset`.

## GitHub Actions on `main`

All workflows passed on GitHub-hosted runners for commit `ad9b7d7`:
`SecretSentinel Security Scan` (dogfood scan, push event: full history),
`Backend tests` (Ubuntu pytest with real Gitleaks, CI gate self-test, and the
Windows job: `bootstrap_windows.ps1`, the full suite and a `run_scanner.ps1`
demo scan returning the expected blocking result), `Frontend tests` (Vitest,
build, Playwright desktop + mobile) and `Contracts tests` (Hardhat suite plus
Python interop against a locally deployed `ScanRegistry`).

## Not established by these checks

- Fork-PR approval behaviour and required-check merge blocking must be
  verified on GitHub after configuring a ruleset
  ([CI_SETUP.md](CI_SETUP.md)). A committed workflow alone does not enable
  branch protection.
- Windows coverage comes from the `windows-latest` CI job (one green run so
  far; it is still marked `continue-on-error` until it has a longer history).
  Tests using the POSIX fake scanner are skipped there.
- The blockchain extension was not deployed to Sepolia or validated against a
  live network.
