<#
.SYNOPSIS
  One-time local setup for SecretSentinel on Windows 11 (no Docker, no VM).

.DESCRIPTION
  * checks Python (3.11+), Git and Node.js (20.19+)
  * creates .venv and installs the backend (editable) with dev extras
  * downloads the PINNED Gitleaks release into tools\gitleaks and verifies its SHA-256
  * installs dashboard dependencies (npm ci) unless -SkipFrontend
  * creates .env from .env.example (if missing) pointing at the local tools and a
    sample-repos folder

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\bootstrap_windows.ps1
#>
[CmdletBinding()]
param(
  [switch]$SkipFrontend,
  [string]$GitleaksVersion = "8.30.1",
  # SHA-256 of gitleaks_<version>_windows_x64.zip from the official release checksums.
  [string]$GitleaksSha256 = "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Need($cmd, $hint) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "$cmd not found. $hint" }
}

Step "Checking prerequisites"
Need python "Install Python 3.11+ from https://www.python.org/downloads/ (tick 'Add python.exe to PATH') or: winget install Python.Python.3.12"
Need git "Install Git: winget install Git.Git"
$pyVersion = (& python -c "import sys; print('%d.%d' % sys.version_info[:2])").Trim()
if ([version]$pyVersion -lt [version]"3.11") { throw "Python $pyVersion found; 3.11 or newer is required." }
Write-Host "    Python $pyVersion, $(git --version)"
if (-not $SkipFrontend) {
  Need node "Install Node.js LTS: winget install OpenJS.NodeJS.LTS (or re-run with -SkipFrontend)"
  $nodeVersion = (& node --version).TrimStart("v")
  if ([version]$nodeVersion -lt [version]"20.19") { throw "Node $nodeVersion found; 20.19 or newer is required." }
  Write-Host "    Node $nodeVersion"
}

Step "Creating virtual environment (.venv)"
if (-not (Test-Path ".venv")) { python -m venv .venv }
$py = Join-Path $Root ".venv\Scripts\python.exe"
& $py -m pip install --disable-pip-version-check --quiet --upgrade pip
& $py -m pip install --disable-pip-version-check --quiet -e "backend[dev]"

Step "Installing Gitleaks $GitleaksVersion (checksum verified)"
$toolDir = Join-Path $Root "tools\gitleaks"
$exe = Join-Path $toolDir "gitleaks.exe"
New-Item -ItemType Directory -Force -Path $toolDir | Out-Null
$zipName = "gitleaks_${GitleaksVersion}_windows_x64.zip"
$zipPath = Join-Path $toolDir $zipName
if (-not (Test-Path $exe)) {
  $url = "https://github.com/gitleaks/gitleaks/releases/download/v$GitleaksVersion/$zipName"
  Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
  $actual = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLower()
  if ($actual -ne $GitleaksSha256.ToLower()) {
    Remove-Item $zipPath -Force
    throw "Checksum mismatch for $zipName (expected $GitleaksSha256, got $actual). Aborting."
  }
  Expand-Archive -Path $zipPath -DestinationPath $toolDir -Force
  Remove-Item $zipPath -Force
}
& $exe version

if (-not $SkipFrontend) {
  Step "Installing dashboard dependencies (npm ci)"
  Push-Location frontend
  try { npm ci --no-audit --no-fund } finally { Pop-Location }
}

Step "Preparing .env and sample-repos"
$samples = Join-Path $Root "sample-repos"
New-Item -ItemType Directory -Force -Path $samples | Out-Null
if (-not (Test-Path ".env")) {
  $content = Get-Content ".env.example" -Raw
  $content = $content -replace "(?m)^GITLEAKS_PATH=.*$", "GITLEAKS_PATH=$exe"
  $content = $content -replace "(?m)^SCAN_ROOT_ALLOWLIST=.*$", "SCAN_ROOT_ALLOWLIST=$samples"
  $content = $content -replace "(?m)^DB_URL=.*$", "# DB_URL=   (default: %USERPROFILE%\.secretsentinel\secretsentinel.db)"
  Set-Content -Path ".env" -Value $content -Encoding utf8
  Write-Host "    Created .env (never commit it)."
}

& $py -m secretsentinel doctor --gitleaks $exe

Write-Host ""
Write-Host "Setup complete. Next steps:" -ForegroundColor Green
Write-Host "  .\.venv\Scripts\Activate.ps1"
Write-Host "  secretsentinel demo create sample-repos\demo"
Write-Host "  secretsentinel scan both sample-repos\demo --gitleaks `"$exe`""
Write-Host "  secretsentinel serve --env-file .env        # API + built dashboard on http://127.0.0.1:8000"
Write-Host "  cd frontend; npm run dev                     # or the live-reload dashboard on http://127.0.0.1:5173"
