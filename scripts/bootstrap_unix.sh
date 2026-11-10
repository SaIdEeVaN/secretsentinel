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

# Usage: scripts/bootstrap_unix.sh [--dev]   (--dev adds test + optional blockchain extras)
extras=""
[[ "${1:-}" == "--dev" ]] && extras="[dev]"

command -v git >/dev/null || { echo "git is required" >&2; exit 1; }

# Python 3.11-3.14: every dependency publishes prebuilt wheels for these.
supported() { "$1" -c 'import sys; sys.exit(0 if (3, 11) <= sys.version_info[:2] <= (3, 14) else 1)' 2>/dev/null; }
python=""
for candidate in python3 python3.13 python3.12 python3.14 python3.11; do
  if command -v "$candidate" >/dev/null && supported "$candidate"; then python="$candidate"; break; fi
done
[[ -n "$python" ]] || { echo "No supported Python found: install Python 3.12 (3.11-3.14 supported)." >&2; exit 1; }
echo "Using $($python --version) ($python)"

if [[ -x .venv/bin/python ]] && ! supported .venv/bin/python; then
  echo "Existing .venv uses an unsupported Python; recreating it."
  rm -rf .venv
fi
[[ -x .venv/bin/python ]] || "$python" -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check -q --upgrade pip
.venv/bin/python -m pip install --disable-pip-version-check -q -e "backend${extras}"

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
