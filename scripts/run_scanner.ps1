<#
.SYNOPSIS
  Run a SecretSentinel scan from PowerShell using the project's .venv and tools.

.EXAMPLE
  scripts\run_scanner.ps1 -Path C:\code\my-dapp -Mode both
  scripts\run_scanner.ps1 -Path . -Mode git -Since origin/main -FailOn critical
  scripts\run_scanner.ps1 -Path . -Format json -Output safe-report.json -NoDb

.NOTES
  Exit codes: 0 pass, 1 blocking findings, 2 configuration error, 3 scan error.
#>
[CmdletBinding()]
param(
  [string]$Path = ".",
  [ValidateSet("dir", "git", "both")][string]$Mode = "both",
  [ValidateSet("critical", "high", "medium", "low", "none")][string]$FailOn,
  [ValidateSet("text", "json", "sarif", "csv")][string]$Format = "text",
  [string]$Output,
  [string]$Since,
  [switch]$NoDb,
  [switch]$VerboseRemediation
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$py = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { throw "Run scripts\bootstrap_windows.ps1 first (.venv not found)." }

$localGitleaks = Join-Path $Root "tools\gitleaks\gitleaks.exe"
if (-not $env:GITLEAKS_PATH -and (Test-Path $localGitleaks)) { $env:GITLEAKS_PATH = $localGitleaks }

$cliArgs = @("-m", "secretsentinel", "scan", $Mode, $Path, "--format", $Format)
if ($FailOn) { $cliArgs += @("--fail-on", $FailOn) }
if ($Output) { $cliArgs += @("--output", $Output) }
if ($Since) { $cliArgs += @("--since", $Since) }
if ($NoDb) { $cliArgs += "--no-db" }
if ($VerboseRemediation) { $cliArgs += "--verbose" }

& $py @cliArgs
exit $LASTEXITCODE
