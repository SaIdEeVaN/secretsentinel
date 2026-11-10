# SecretSentinel

A local-first secret scanner and dashboard for application and Web3 projects.
Scan current files and Git history, review redacted findings, and fail pull
request checks when a blocking exposure is found. No Docker or wallet is needed.

Built from the [product requirements](docs/PRD.md). The core workflow includes:

- Gitleaks default rules plus contextual Web3 signing-key, mnemonic and RPC rules.
- Directory, Git history and combined scans, with distinct error/cancelled states.
- A FastAPI/SQLite backend and React dashboard with history, filters, triage,
  remediation, reviewed suppressions, and JSON/CSV/SARIF downloads.
- A CLI, reviewed baselines and a fail-closed GitHub Actions security check.
- Synthetic demo repositories and automated security, API, UI and browser tests.

The scanner never uses a detected credential, contacts a wallet, or runs code
from a scanned repository. Reports contain location and classification metadata,
never the secret value or source excerpt. A clean scan is **not a guarantee that
the repository is free of secrets**.

## Quick start: Windows 11

Install Git, Python 3.12 and Node.js LTS (22 or 24), then open PowerShell in this
checkout. Python **3.11-3.14** is supported. Python 3.15 is not yet: PyYAML has
no Windows packages for it, so pip would need the Microsoft C++ Build Tools. The
setup script picks a supported version via `python` or the `py` launcher.

```powershell
winget install Git.Git
winget install Python.Python.3.12
winget install OpenJS.NodeJS.LTS
# Reopen PowerShell if these commands changed PATH.
./scripts/bootstrap_windows.ps1
```

The script creates `.venv`, installs the backend and frontend, verifies the
Gitleaks 8.30.1 download, and creates a local `.env` if none exists. Review that
file and keep it out of source control. By default the dashboard can scan only
folders under `sample-repos`.

Run the backend in one terminal:

```powershell
.\.venv\Scripts\python.exe -m secretsentinel serve --env-file .env
```

Run the dashboard in another terminal:

```powershell
cd frontend
npm run dev
```

Open the address printed by Vite (normally port 5173). Select **Create demo
repository**, start the recommended combined scan, then open its findings. The
demo has synthetic values, including one removed from the current tree but
retained in Git history. A failing demo scan is expected.

To serve the built dashboard directly from the backend instead:

```powershell
cd frontend
npm run build
cd ..
.\.venv\Scripts\python.exe -m secretsentinel serve --env-file .env
```

The combined application then runs on loopback port 8000.

## Linux and macOS

Python 3.11+ (3.12 tested), Git and Node.js 22/24 LTS are prerequisites.

```bash
bash scripts/bootstrap_unix.sh
source .venv/bin/activate
secretsentinel serve --env-file .env
```

In another terminal, run `cd frontend && npm run dev`. Linux x64 setup installs
a checksum-verified Gitleaks when none is on PATH. On macOS or other platforms,
install the official Gitleaks executable first. The pinned release and checksums
are recorded in the bootstrap scripts and workflows.

## CLI scanning

The CLI does **not** auto-load `.env` from a scanned directory. Configure
`GITLEAKS_PATH` explicitly or put the trusted executable on PATH. The backend
loads only the env file explicitly passed to `serve --env-file`.

```powershell
$env:GITLEAKS_PATH = (Resolve-Path tools\gitleaks\gitleaks.exe).Path
.\.venv\Scripts\python.exe -m secretsentinel doctor
.\.venv\Scripts\python.exe -m secretsentinel demo create sample-repos\demo
.\.venv\Scripts\python.exe -m secretsentinel scan dir sample-repos\demo
.\.venv\Scripts\python.exe -m secretsentinel scan git sample-repos\demo
.\.venv\Scripts\python.exe -m secretsentinel scan both sample-repos\demo --format json --output safe-report.json
```

On Unix, use the activated `secretsentinel` command and forward-slash paths;
set `GITLEAKS_PATH` to `tools/gitleaks/gitleaks` if it is not on PATH. `scan`
records sanitized history in SQLite; `check` is the CI form and never writes to
the database. Use `--help` to see modes, scope, policy and output options.

Exit codes: **0** policy passed, **1** blocking findings, **2** invalid input or
policy, **3** scanner/process error. Every nonzero exit fails a CI check.

## Configuration and policy

See [.env.example](.env.example) for all supported settings. In local mode no
API keys are needed. The default database is under your home directory in
`.secretsentinel`; set `DB_URL` to another writable SQLite path if needed.

- `SCAN_ROOT_ALLOWLIST`: absolute folders the dashboard may scan, separated by
  `;` on Windows or `:` on Unix. Empty means dashboard scanning is disabled.
- `GITLEAKS_PATH`: a trusted executable; `SCANNER_TIMEOUT_SECONDS`: scan deadline.
- `FAIL_ON`: `critical`, `high` (default), `medium`, `low` or `none`.
- `ENABLE_BLOCKCHAIN=false`: the optional attestation code stays disabled.

[.secretsentinel.yml](.secretsentinel.yml) defines the repository's explicit
policy. Suppressions require a reason, reviewer and expiry date. Acknowledging
or marking a finding resolved does not bypass a new scan's blocking policy.
The dashboard's **Rules & Policy** page explains reviewed suppressions.

For a reviewed metadata-only baseline:

```text
secretsentinel baseline create <local-folder> --mode both --reason "Reviewed synthetic fixtures" --reviewer "maintainer" --expires 2027-01-01 --output .secretsentinel-baseline.json
```

Choose an expiry within the next year, review every entry, then reference the
file with `baseline: .secretsentinel-baseline.json` in the policy. Never baseline
a real exposure instead of rotating/revoking the credential.

## Tests

Install the dev extras first (`bootstrap_windows.ps1 -Dev`, `bootstrap_unix.sh --dev`
or `pip install -e "backend[dev]"`), activate `.venv`, and make Gitleaks available
via `GITLEAKS_PATH` or PATH.

```bash
cd backend
python -m pytest -q
cd ../frontend
npm test
npm run build
cd ..
python scripts/check_no_raw_secrets.py --self-test
bash scripts/ci_gate_selftest.sh
```

The real browser suite uses an isolated temporary database and scan roots,
starts its own backend, and checks desktop and phone layouts against real scans.
It covers combined history scanning, triage, all three downloads, a leak fixed
and rescanned, and rejected out-of-root paths. It never uses the local `.env`.

```bash
cd frontend
npx playwright install chromium
npm run test:e2e
```

With an existing Chromium executable, set `PLAYWRIGHT_CHROMIUM_EXECUTABLE`
instead of downloading one. `SECRETSENTINEL_PYTHON` can select a backend Python
interpreter; the browser runner otherwise uses `.venv`, then `python`.

## CI and further documentation

- [Hosted dashboard on Render (results uploaded from GitHub Actions)](docs/HOSTING.md)
- [Windows 11 setup in detail](docs/SETUP_WINDOWS.md)
- [Required GitHub security check setup](docs/CI_SETUP.md)
- [Architecture and API](docs/ARCHITECTURE.md)
- [Security model and limitations](docs/SECURITY.md)
- [Threat model (PRD section 16)](docs/THREAT_MODEL.md)
- [Test plan and PRD test-case matrix](docs/TEST_PLAN.md)
- [Synthetic demonstration](docs/DEMO.md)
- [Local validation results and remaining external checks](docs/VALIDATION.md)

CI runs on pull requests and pushes to `main`. A maintainer must configure the
required status check in GitHub settings to block merges; the workflow alone
cannot enforce branch protection. The security job scans all pull requests.

For a private web dashboard, [`render.yaml`](render.yaml) deploys a view-only
copy to Render: GitHub Actions scans your repositories and uploads only the
sanitized report, and you sign in with a token. The hosted copy never scans or
clones code, and it uses one shared token rather than per-user accounts. See
[docs/HOSTING.md](docs/HOSTING.md).

## Optional: signed scan attestations (P2)

Disabled by default (`ENABLE_BLOCKCHAIN=false`) and not needed for scanning.
When enabled, `secretsentinel attest create <scan-id>` signs a canonical,
non-sensitive scan summary (scan id, salted commit commitment, tool/ruleset/
policy digests, status and counts) and `attest publish` registers only its
SHA-256 digest in [`contracts/src/ScanRegistry.sol`](contracts/src/ScanRegistry.sol).
`attest verify bundle.json --onchain` (or the dashboard's **Attestations** page)
checks the digest, signature, trusted signer, chain binding and registry record.

The contract and the Python client are tested on a local Hardhat chain
(`cd contracts && npm ci && npx hardhat test`, plus the `chain` interop tests in
CI). Nothing has been deployed to Sepolia by this project. A verified
attestation shows **who attested to a scan result**; it never proves the code
is secure. Use a dedicated publishing key referenced via
`ATTESTATION_SIGNER_KEY_REFERENCE=env:VAR` or `keystore:<path>`, never a raw key.

## Troubleshooting

- **`Failed building wheel for pyyaml` / `Microsoft Visual C++ 14.0 or greater is
  required`:** your Python is too new (e.g. 3.15). Install Python 3.12
  (`winget install Python.Python.3.12`) and re-run the bootstrap; it recreates `.venv`.
- **Scanner not found:** check `GITLEAKS_PATH`; the CLI will not load `.env`.
- **Path not allowed:** add the folder to `SCAN_ROOT_ALLOWLIST` and restart the
  backend with `--env-file .env`.
- **No Git repository:** select directory mode for a folder without commits.
- **Dashboard cannot reach the API:** start the backend on port 8000; Vite proxies
  `/api` there. Check `/api/v1/health` locally.
- **PowerShell script blocked:** use a process-scoped policy permitted by your
  organization, or run the documented commands manually. No global policy change
  is required by the application.
- **Unwritable package cache:** point `PIP_CACHE_DIR` and `npm_config_cache` at
  writable directories.
- **Playwright cannot find a browser:** run `npx playwright install chromium`, or set
  `PLAYWRIGHT_CHROMIUM_EXECUTABLE` to an existing Chromium binary.

Original code is [MIT licensed](LICENSE); dependencies retain their own licenses.
