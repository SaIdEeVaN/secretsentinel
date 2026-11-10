<#
.SYNOPSIS
  One-time local setup for SecretSentinel on Windows 11 (no Docker, no VM).

.DESCRIPTION
  * finds a SUPPORTED Python (3.11-3.14; prefers the `python` on PATH, then the
    `py` launcher). Python 3.15 is refused for now: PyYAML has no Windows wheels
    for it yet, so pip would need the Microsoft C++ Build Tools.
  * creates .venv (recreating one built with an unsupported Python) and installs
    the backend in editable mode. -Dev adds test and blockchain extras.
  * downloads the PINNED Gitleaks release into tools\gitleaks and verifies its SHA-256
  * installs dashboard dependencies (npm ci) unless -SkipFrontend
  * creates .env from .env.example (if missing) pointing at the local tools and a
    sample-repos folder
  Every step stops the script on failure.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\bootstrap_windows.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\bootstrap_windows.ps1 -Dev   # contributors: tests + optional extras
#>
[CmdletBinding()]
param(
  [switch]$SkipFrontend,
  [switch]$Dev,
  [string]$GitleaksVersion = "8.30.1",
  # SHA-256 of gitleaks_<version>_windows_x64.zip from the official release checksums.
  [string]$GitleaksSha256 = "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Root

# Versions with prebuilt Windows wheels for every dependency, in order of preference.
$SupportedPython = @("3.13", "3.12", "3.14", "3.11")
$PythonHelp = "Install Python 3.12 (winget install Python.Python.3.12), then re-run this script. " +
  "Python 3.11-3.14 are supported; 3.15 is too new for some dependencies' Windows packages."

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Need($cmd, $hint) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "$cmd not found. $hint" }
}
function Invoke-Checked([string]$What, [string]$Exe, [string[]]$Arguments) {
  & $Exe @Arguments
  if ($LASTEXITCODE -ne 0) { throw "$What failed (exit code $LASTEXITCODE). See the output above." }
}
function Get-PyVersion([string[]]$Cmd) {
  $rest = @()
  if ($Cmd.Length -gt 1) { $rest = $Cmd[1..($Cmd.Length - 1)] }
  try {
    $out = & $Cmd[0] @rest -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
    if ($LASTEXITCODE -eq 0 -and $out) { return ([string]($out | Select-Object -First 1)).Trim() }
  } catch { }
  return $null
}
function Find-Python {
  if (Get-Command python -ErrorAction SilentlyContinue) {
    $v = Get-PyVersion @("python")
    if ($v -and ($SupportedPython -contains $v)) { return @{ Cmd = @("python"); Version = $v } }
    if ($v) { Write-Host "    'python' on PATH is $v (not supported); looking for 3.11-3.14 via the py launcher..." -ForegroundColor Yellow }
  }
  if (Get-Command py -ErrorAction SilentlyContinue) {
    foreach ($s in $SupportedPython) {
      if ((Get-PyVersion @("py", "-$s")) -eq $s) { return @{ Cmd = @("py", "-$s"); Version = $s } }
    }
  }
  return $null
}

Step "Checking prerequisites"
Need git "Install Git: winget install Git.Git"
$Python = Find-Python
if (-not $Python) { throw "No supported Python found. $PythonHelp" }
Write-Host "    Python $($Python.Version) ($($Python.Cmd -join ' ')), $(git --version)"
if (-not $SkipFrontend) {
  Need node "Install Node.js LTS: winget install OpenJS.NodeJS.LTS (or re-run with -SkipFrontend)"
  $nodeVersion = (& node --version).TrimStart("v")
  if ([version]$nodeVersion -lt [version]"20.19") { throw "Node $nodeVersion found; 20.19 or newer is required." }
  Write-Host "    Node $nodeVersion"
}
if ($Root -match "OneDrive") {
  Write-Host "    Note: this folder is synced by OneDrive. Syncing .venv and node_modules is slow and can lock files;" -ForegroundColor Yellow
  Write-Host "    consider moving the project to a non-synced folder such as C:\dev\secretsentinel." -ForegroundColor Yellow
}

Step "Creating virtual environment (.venv)"
$venvDir = Join-Path $Root ".venv"
$py = Join-Path $venvDir "Scripts\python.exe"
if (Test-Path $py) {
  $venvVersion = Get-PyVersion @($py)
  if (-not ($venvVersion -and ($SupportedPython -contains $venvVersion))) {
    Write-Host "    Existing .venv uses Python $venvVersion (not supported); recreating it with $($Python.Version)." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $venvDir
  }
} elseif (Test-Path $venvDir) {
  Remove-Item -Recurse -Force $venvDir  # incomplete venv from an earlier failed run
}
if (-not (Test-Path $py)) {
  $pyRest = @()
  if ($Python.Cmd.Length -gt 1) { $pyRest = $Python.Cmd[1..($Python.Cmd.Length - 1)] }
  Invoke-Checked "Creating .venv" $Python.Cmd[0] ($pyRest + @("-m", "venv", $venvDir))
}
Invoke-Checked "Upgrading pip" $py @("-m", "pip", "install", "--disable-pip-version-check", "--quiet", "--upgrade", "pip")
$target = if ($Dev) { "backend[dev]" } else { "backend" }
Write-Host "    Installing $target ..."
Invoke-Checked "Installing the backend ($target)" $py @("-m", "pip", "install", "--disable-pip-version-check", "--quiet", "-e", $target)

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
Invoke-Checked "Running gitleaks version" $exe @("version")

if (-not $SkipFrontend) {
  Step "Installing dashboard dependencies (npm ci)"
  Push-Location frontend
  try { Invoke-Checked "npm ci" "npm" @("ci", "--no-audit", "--no-fund") } finally { Pop-Location }
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
Write-Host "Setup complete. Next steps (PowerShell):" -ForegroundColor Green
Write-Host "  .\.venv\Scripts\Activate.ps1                 (Command Prompt: .venv\Scripts\activate.bat)"
Write-Host "  secretsentinel demo create sample-repos\demo"
Write-Host "  secretsentinel scan both sample-repos\demo --gitleaks `"$exe`""
Write-Host "  secretsentinel serve --env-file .env        # API + built dashboard on http://127.0.0.1:8000"
Write-Host "  cd frontend; npm run dev                     # or the live-reload dashboard on http://127.0.0.1:5173"
