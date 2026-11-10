# Local MVP validation

Validated on 10 November 2026 in the Linux cloud workspace using Python 3.12.14,
Node.js 24.22.1, npm 11.9.0, Gitleaks 8.30.1 and the available system Chromium.
No live credentials, wallet connections, hosted deployments or Sepolia calls
were used.

| Check | Observed result |
|---|---|
| `cd backend && python -m pytest -q` | 203 passed; no skipped tests |
| `cd frontend && npm test` | 19 passed across 3 files |
| `cd frontend && npm run test:e2e` | Production build passed; 6 browser tests passed |
| `python scripts/check_no_raw_secrets.py --self-test` | Passed, 33 canaries loaded |
| `bash scripts/ci_gate_selftest.sh` | Clean/leaking PRs, errors, formats and redaction checks passed |
| Workflow YAML parsing and `git diff --check` | Passed |

## Behaviors exercised

- Real Gitleaks directory, Git-history and combined scans; historic-only and
  uncommitted synthetic findings, benign fixtures, scanner errors and timeouts.
- Safe persistence, path/symlink validation, filtering, audited triage, reviewed
  suppression, expiry rules and cancellation.
- JSON/CSV/SARIF downloads, including more findings than the API page limit,
  spreadsheet formula neutralization and rejection of incomplete/stale reviews.
- Desktop and 390-pixel phone browser flows against a real isolated backend:
  demo creation, combined scan, historic-key visibility, triage, downloads,
  blocked-to-clean directory rescans, retained historical findings, rejected
  paths and mobile navigation.
- Absence of the planted value from captured browser responses, rendered data,
  browser storage, SQLite and its journal files in the fix-and-rescan scenario.
- UI regressions for unknown policy results, cancelled-action errors, resetting
  pagination and fetching final findings after a scan-completion race.

## Not established by these local checks

GitHub-hosted workflow results, fork approval behavior and required-check merge
blocking must be verified in GitHub after pushing and configuring the ruleset.
See [CI_SETUP.md](CI_SETUP.md). A committed workflow alone does not enable branch
protection. Windows is covered by an experimental CI job and was not executed
in this Linux workspace. The optional blockchain extension was not deployed or
validated against a live network. Detection-rate and latency targets in the PRD
are targets, not measured production claims.
