# Windows 11 setup

SecretSentinel runs natively on Windows 11 with PowerShell. Docker, WSL and
virtual machines are **not** required.

## 1. Prerequisites

```powershell
winget install Git.Git
winget install Python.Python.3.12
winget install OpenJS.NodeJS.LTS
```

Close and reopen PowerShell so `git`, `python` and `node` are on PATH, then check:

```powershell
git --version
python --version   # 3.11 or newer
node --version     # 20.19 or newer
```

If `python` opens the Microsoft Store, disable the *App execution aliases* for
`python.exe`/`python3.exe` in **Settings → Apps → Advanced app settings**.

## 2. Bootstrap

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\bootstrap_windows.ps1
```

`-ExecutionPolicy Bypass` applies only to that one process; no global policy is
changed. The script:

1. checks Python, Git and Node versions;
2. creates `.venv` and installs the backend (`pip install -e backend[dev]`);
3. downloads Gitleaks **8.30.1** for Windows x64 into `tools\gitleaks\` and
   verifies its SHA-256 against the pinned value
   `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e`
   (aborting on mismatch);
4. runs `npm ci` for the dashboard (skip with `-SkipFrontend`);
5. creates `.env` from `.env.example` with `GITLEAKS_PATH` and
   `SCAN_ROOT_ALLOWLIST` pointing at `tools\gitleaks\gitleaks.exe` and
   `sample-repos\`;
6. runs `secretsentinel doctor`.

To install Gitleaks by hand instead, download `gitleaks_8.30.1_windows_x64.zip`
from the official release page and compare
`(Get-FileHash .\gitleaks_8.30.1_windows_x64.zip -Algorithm SHA256).Hash` with
the value above before extracting it.

## 3. First scan

Windows' default execution policy also blocks `Activate.ps1` and the helper
scripts. Allow scripts for the current PowerShell window only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
secretsentinel demo create sample-repos\demo
scripts\run_scanner.ps1 -Path sample-repos\demo -Mode both
```

The demo contains **synthetic** leaks only, so a FAIL result (exit code 1) is
expected. Exit codes: 0 pass, 1 blocking findings, 2 configuration error,
3 scan error.

## 4. Dashboard

```powershell
cd frontend; npm run build; cd ..
secretsentinel serve --env-file .env
```

Open <http://127.0.0.1:8000>. For live reload, run `secretsentinel serve
--env-file .env` in one terminal and `cd frontend; npm run dev` in another, then
open <http://127.0.0.1:5173>. Only folders inside `SCAN_ROOT_ALLOWLIST` can be
registered; separate several roots with `;`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `SCANNER_NOT_FOUND` | Set `GITLEAKS_PATH` (the CLI never reads `.env` on its own) or pass `--gitleaks tools\gitleaks\gitleaks.exe`. |
| Antivirus quarantines `gitleaks.exe` | Restore it from quarantine after verifying the checksum, or add an exclusion for `tools\gitleaks\`. |
| `UNSUPPORTED_REPO` in git mode | Scan the repository **root**, or use `-Mode dir` for folders that are not Git repositories. |
| Git reports *dubious ownership* | `git config --global --add safe.directory C:/path/to/repo` for repositories you trust to read. |
| `PATH_NOT_ALLOWED` in the dashboard | Add the parent folder to `SCAN_ROOT_ALLOWLIST` in `.env` and restart `serve`. |
| Port 8000 busy | `secretsentinel serve --env-file .env --port 8010` (and update the Vite proxy target if using `npm run dev`). |
| Long path errors in `node_modules` | `git config --global core.longpaths true`, and enable *Win32 long paths* in Group Policy if needed. |
