#!/usr/bin/env bash
# Local setup for Linux/macOS (Windows users: scripts/bootstrap_windows.ps1).
# Creates .venv, installs the backend, installs a checksum-verified Gitleaks into
# tools/gitleaks (Linux x64 only; elsewhere install Gitleaks yourself), installs
# dashboard dependencies and creates .env if missing.
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"

version="8.30.1"
sha256_linux_x64="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"

command -v python3 >/dev/null || { echo "python3 (3.11+) is required" >&2; exit 1; }
command -v git >/dev/null || { echo "git is required" >&2; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || { echo "Python 3.11+ required" >&2; exit 1; }

[[ -d .venv ]] || python3 -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check -q --upgrade pip
.venv/bin/python -m pip install --disable-pip-version-check -q -e "backend[dev]"

gitleaks_path="$(command -v gitleaks || true)"
if [[ -z "$gitleaks_path" ]]; then
  if [[ "$(uname -s)-$(uname -m)" == "Linux-x86_64" ]]; then
    bash scripts/install_gitleaks.sh "$version" "$sha256_linux_x64" "$root/tools/gitleaks"
    gitleaks_path="$root/tools/gitleaks/gitleaks"
  else
    echo "Install Gitleaks $version (e.g. 'brew install gitleaks') and re-run." >&2
    exit 1
  fi
fi

if command -v npm >/dev/null; then (cd frontend && npm ci --no-audit --no-fund); else echo "npm not found: skipping dashboard dependencies"; fi

mkdir -p sample-repos
if [[ ! -f .env ]]; then
  sed -e "s|^GITLEAKS_PATH=.*|GITLEAKS_PATH=$gitleaks_path|" \
      -e "s|^SCAN_ROOT_ALLOWLIST=.*|SCAN_ROOT_ALLOWLIST=$root/sample-repos|" \
      -e "s|^DB_URL=.*|# DB_URL=   (default: ~/.secretsentinel/secretsentinel.db)|" .env.example > .env
  echo "Created .env (never commit it)."
fi
.venv/bin/secretsentinel doctor --gitleaks "$gitleaks_path"
echo
echo "Next: source .venv/bin/activate && secretsentinel demo create sample-repos/demo && secretsentinel scan both sample-repos/demo"
