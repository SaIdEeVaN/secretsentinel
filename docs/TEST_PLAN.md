# Test plan

## Suites

| Suite | Command | CI job |
|---|---|---|
| Backend unit + integration (real Gitleaks) | `cd backend && python -m pytest -q` | `Backend tests / pytest (ubuntu, real Gitleaks)` |
| Backend on Windows (via `bootstrap_windows.ps1`) | same | `Backend tests / pytest (windows, experimental)` |
| CI gate self-test (exit codes, PR flow, redaction) | `bash scripts/ci_gate_selftest.sh` | `Backend tests / CI gate self-test` |
| Frontend unit (Vitest + Testing Library) | `cd frontend && npm test` | `Frontend tests / vitest + build` |
| Browser E2E (Playwright, desktop + 390 px phone, real backend) | `cd frontend && npm run test:e2e` | `Frontend tests / browser MVP` |
| Contract (Hardhat) | `cd contracts && npx hardhat test` | `Contracts tests / ScanRegistry + Python interop` |
| Python ↔ contract interop (local chain) | `pytest -m chain tests/test_chain_interop.py` with `SECRETSENTINEL_TEST_RPC_URL`/`SECRETSENTINEL_TEST_REGISTRY` | same |
| Dogfood scan of this repository | `secretsentinel check . --mode both` | `SecretSentinel Security Scan / secret-scan` |

Tests that need a real Gitleaks binary are marked `gitleaks` and are skipped
(not failed) when none is installed; CI always installs the pinned release.

## Fixtures and canaries

Positive fixtures live in `rules/fixtures/synthetic_positive/` as **templates**
with placeholders such as `{{SYNTH:hex64:evm-env}}`. Values are generated at test
time from public labels (`secretsentinel/fixtures.py`), so no secret-shaped
value is committed. Every generated value is a **canary**: the no-raw-secrets
tests search CLI output, all export formats, GitHub annotations/summaries, API
responses, the SQLite dump and logs for each canary and its 20-character
prefix/suffix. `scripts/check_no_raw_secrets.py --self-test` proves the
detector itself fires. Benign negatives in `rules/fixtures/benign_negative/` are
committed verbatim. `rules/fixtures/manifest.yaml` maps each fixture to its
expected rule.

## Acceptance targets (PRD 4.3)

| Metric | Target | How measured |
|---|---|---|
| Synthetic detection | ≥ 90% | `test_rules.py::test_detection_rate_and_false_positive_rate` over the manifest |
| False positives | ≤ 10% | same test, benign negatives with any finding |
| Safe reporting | 0 canaries anywhere | `test_no_raw_secrets.py`, gate self-test, E2E browser/DB check |
| CI correctness | 100% of leaking fixture PRs fail | `ci_gate_selftest.sh` (`pr-leak`, fixture runs) |
| Latency | ≤ 30 s for < 1,000 files | fixture scan timing (see VALIDATION.md); not a production claim |

The detection/FP numbers are measured on a **curated synthetic fixture set** and
are engineering targets, not a claim about real-world detection rates.

## PRD test-case matrix (18.2)

| ID | Scenario | Automated by |
|---|---|---|
| T01 | Clean directory → completed, 0 findings, pass | `test_scanner.py::test_clean_scan_passes_T01`; gate self-test `clean-dir` |
| T02 | Synthetic API token → classified, redacted everywhere | `test_rules.py::test_T02_service_tokens_detected`; `test_no_raw_secrets.py` |
| T03 | Leak removed in HEAD but present in history → found by `git` | `test_scanner.py::test_T03_history_only_leak_found_by_git_not_dir`; demo repo; E2E |
| T04 | Uncommitted synthetic secret → found by `dir` | `test_scanner.py::test_T04_uncommitted_leak_found_by_dir_not_git` |
| T05 | 64-hex tx hash without key context → not a private key | `test_rules.py::test_T05_T07_hashes_and_sentences_not_signing_secrets` |
| T06 | EVM-like secret in `PRIVATE_KEY` → critical | `test_rules.py::test_T06_private_key_assignment_is_critical` |
| T07 | 12-word harmless sentence → not a seed | `test_rules.py::test_T05_T07_...` (`sentences.md`) |
| T08 | Gitleaks missing → failed, never pass | `test_scanner.py::test_T08_...`; `test_cli.py::test_missing_scanner_exit_code`; gate `missing-scanner` |
| T09 | Scanner timeout → failed with safe error | `test_scanner.py::test_T09_timeout_fails_with_safe_error`; `test_cli.py` |
| T10 | Unexpected field holding a secret → omitted | `test_sanitizer.py::test_unexpected_fields_are_dropped_and_counted_T10` |
| T11 | Unreviewed suppression → cannot suppress | `test_policy.py::test_T11_unreviewed_or_expired_suppression_does_not_apply` |
| T12 | PR with blocking finding → check fails | gate self-test `pr-leak`; `secret-scan.yml` on GitHub (see CI_SETUP.md) |
| T13 | PR from fork → works without secrets | workflow design (`pull_request`, read-only, no secrets); verify on GitHub |
| T14 | Out-of-root path → rejected | `test_security.py::test_out_of_root_path_rejected_T14`; `test_api.py::test_register_rejects_out_of_root_T14`; E2E |
| T15 | Attestation modified after registration → fails | `test_attestation.py::test_T15_modified_payload_fails`; `test_chain_interop.py` |
| T16 | Wrong signer or chain → fails | `test_attestation.py::test_T16_*`; `test_chain_interop.py::test_wrong_chain_id_is_refused` |

## Manual checks still required on GitHub

T12/T13 enforcement depends on repository settings: register `secret-scan` as a
required status check, open a disposable PR with a synthetic leak, confirm the
merge button is blocked, and repeat from a fork. Steps: [CI_SETUP.md](CI_SETUP.md).
