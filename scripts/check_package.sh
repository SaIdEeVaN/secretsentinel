#!/usr/bin/env bash
# Check a built wheel the way a PyPI user gets it: install it into a clean
# virtualenv, then, OUTSIDE the source checkout, confirm that
#   1. the installed ruleset is identical to rules/ in this checkout, and
#   2. a scan of the synthetic demo repository finds blocking findings (exit 1).
#
#   GITLEAKS_PATH=/path/to/gitleaks scripts/check_package.sh <dist-dir>
#
# Used by .github/workflows/backend-tests.yml and release.yml. Prints no secret
# values: the demo leaks are synthetic and scan output is redacted anyway.
set -euo pipefail

dist="$(cd "${1:?dist directory required}" && pwd)"
checkout="$(cd "$(dirname "$0")/.." && pwd)"
: "${GITLEAKS_PATH:?set GITLEAKS_PATH to a Gitleaks executable}"

wheels=("$dist"/*.whl)
[[ ${#wheels[@]} -eq 1 && -f "${wheels[0]}" ]] || { echo "expected exactly one wheel in $dist" >&2; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
python3 -m venv "$work/venv"
"$work/venv/bin/python" -m pip install --disable-pip-version-check --quiet "${wheels[0]}"
cd "$work"  # away from the checkout, so nothing can come from source

expected="$(PYTHONPATH="$checkout/backend" SECRETSENTINEL_RULES_DIR="$checkout/rules" "$work/venv/bin/python" -m secretsentinel rules digest)"
actual="$(env -u SECRETSENTINEL_RULES_DIR "$work/venv/bin/secretsentinel" rules digest)"
if [[ "$actual" != "$expected" ]]; then
  echo "installed ruleset differs from rules/: '$actual' vs '$expected'" >&2
  exit 1
fi
echo "ruleset in the wheel matches rules/: $actual"

"$work/venv/bin/secretsentinel" demo create "$work/demo" > /dev/null
set +e
env -u SECRETSENTINEL_RULES_DIR "$work/venv/bin/secretsentinel" check "$work/demo" --mode both --no-policy > /dev/null
code=$?
set -e
if [[ $code -ne 1 ]]; then
  echo "expected exit code 1 (blocking findings in the demo), got $code" >&2
  exit 1
fi
echo "installed CLI found the demo's blocking findings (exit 1)"
