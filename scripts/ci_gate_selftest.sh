#!/usr/bin/env bash
# End-to-end self-test of the CI security gate with the REAL Gitleaks binary.
# Verifies exit codes for clean / leaking / PR-range / misconfigured / missing
# scanner cases, then checks that no synthetic canary leaked into any output.
#
#   PYTHONPATH=backend GITLEAKS_PATH=/path/to/gitleaks scripts/ci_gate_selftest.sh
set -uo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="${PYTHONPATH:-$repo_root/backend}"
export SECRETSENTINEL_RULES_DIR="${SECRETSENTINEL_RULES_DIR:-$repo_root/rules}"
py="${PYTHON:-python}"
work="$(mktemp -d)"
out="$work/outputs"
mkdir -p "$out"
trap 'rm -rf "$work"' EXIT
export GITHUB_STEP_SUMMARY="$out/step-summary.md"
failures=0

expect() {
  local want="$1" name="$2"; shift 2
  "$@" >"$out/$name.stdout" 2>"$out/$name.stderr"
  local got=$?
  if [[ "$got" == "$want" ]]; then
    echo "PASS  $name (exit $got)"
  else
    echo "FAIL  $name: expected exit $want, got $got"
    failures=$((failures + 1))
  fi
}

ss() { "$py" -m secretsentinel "$@"; }

# 1. Clean directory -> 0 (T01)
mkdir -p "$work/clean" && echo "hello" > "$work/clean/README.md"
expect 0 clean-dir ss check "$work/clean" --mode dir --no-policy

# 2. Synthetic fixture set -> 1, in every output format (T02/T06, CI-03)
"$py" -c "from pathlib import Path; from secretsentinel.fixtures import materialize; materialize(Path('$work/fixtures'))"
expect 1 fixtures-text ss check "$work/fixtures" --mode dir --no-policy --github-annotations --github-summary --verbose
for fmt in json sarif csv; do
  expect 1 "fixtures-$fmt" ss check "$work/fixtures" --mode dir --no-policy --format "$fmt" --output "$out/report.$fmt"
done

# 3. Simulated pull request: clean PR passes, PR adding a synthetic key fails (T12)
git_c() { git -C "$work/pr" -c user.name=ci -c user.email=ci@example.invalid -c commit.gpgsign=false "$@"; }
mkdir -p "$work/pr" && git_c init -q && echo base > "$work/pr/a.txt" && git_c add -A && git_c commit -qm base
base="$(git_c rev-parse HEAD)"
echo "docs only" > "$work/pr/b.txt" && git_c add -A && git_c commit -qm "clean change"
expect 0 pr-clean ss check "$work/pr" --mode git --since "$base" --no-policy
clean_head="$(git_c rev-parse HEAD)"
"$py" -c "from secretsentinel.fixtures import synth; print('DEPLOYER_PRIVATE_KEY=0x' + synth('hex64', 'ci-pr-leak'))" > "$work/pr/.env"
git_c add -A && git_c commit -qm "add deploy config"
expect 1 pr-leak ss check "$work/pr" --mode git --since "$clean_head" --no-policy --github-annotations

# 4. Misconfiguration fails closed (CI-04)
mkdir -p "$work/badpolicy" && echo "fail_on: sometimes" > "$work/badpolicy/.secretsentinel.yml"
expect 2 invalid-policy ss check "$work/badpolicy" --mode dir
expect 2 invalid-ref ss check "$work/pr" --mode git --since "--output=/tmp/x"

# 5. Scanner missing -> 3, never pass (T08)
expect 3 missing-scanner ss check "$work/clean" --mode dir --no-policy --gitleaks /nonexistent/gitleaks

# 6. No synthetic secret may appear in any captured output (CI-05)
if "$py" "$repo_root/scripts/check_no_raw_secrets.py" "$out"; then
  echo "PASS  no-raw-secrets"
else
  echo "FAIL  no-raw-secrets"; failures=$((failures + 1))
fi
grep -q "::error file=" "$out/pr-leak.stdout" && echo "PASS  annotations emitted" || { echo "FAIL  annotations"; failures=$((failures + 1)); }

if [[ "$failures" -gt 0 ]]; then
  echo "$failures gate self-test(s) failed"; exit 1
fi
echo "All gate self-tests passed."
