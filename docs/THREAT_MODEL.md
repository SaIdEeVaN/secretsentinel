# Threat model

Scope: the local-first MVP (CLI, loopback API + dashboard, GitHub Actions gate)
and the optional attestation extension. Design principle: **find the secret,
never become another place that leaks it.** See [SECURITY.md](SECURITY.md) for
the condensed security model and user-facing limitations.

## Assets

1. Real and candidate secrets in source files and Git history.
2. Findings metadata (paths, line numbers, commit IDs, rule IDs).
3. The developer workstation and its filesystem.
4. Repository integrity and the CI trust boundary (the merge gate itself).
5. Optional attestation signing keys and on-chain publisher identity.

## Trust boundaries

| Boundary | Rule |
|---|---|
| Scanned repository → scanner | Repository content is hostile **data**. It is never executed, and it cannot configure the scanner. |
| Raw Gitleaks output → application | Only allowlisted metadata fields cross; everything else is dropped. |
| Backend → browser | Loopback only by default; Host, Origin and Content-Type checked; explicit response models. |
| Pull request → CI | No secrets or write tokens; scanner, rules and policy come from the protected base commit. |
| Application → public chain | Only a digest of non-sensitive scan metadata; provenance verified by the client. |

## Threats and mitigations (PRD 16.3)

| Threat | Mitigation in this codebase | Evidence |
|---|---|---|
| Secret printed in logs | `--redact=100`; strict sanitizer; constant error messages; whitelist JSON logger (`core/log.py`); stderr of Gitleaks read only to pick an error code | `test_no_raw_secrets.py`, `ci_gate_selftest.sh` (scans its own log) |
| Raw report uploaded as CI artifact | Reports stay in a private temp dir deleted in `finally`; workflows upload no artifacts; exports are built from sanitized rows | `test_scanner.py::test_temp_files_removed`, export tests |
| Regex false positive | Context-required Web3 rules, entropy floors, hash/digest allowlists, path-based confidence lowering, reviewed expiring suppressions, baselines | `test_rules.py` (0/13 benign fixtures flagged) |
| Regex false negative | Gitleaks defaults kept (`useDefault = true`) plus 18 Web3 rules and 2 gap-filling rules (Twitter/X bearer tokens with a 21-`A` prefix, credentials in URL query strings; see `docs/RULE_AUDIT.md`); `both` mode covers tree + history; documented limits | `test_rules.py` (30/30 synthetic positives) |
| Malicious path / symlink | `Path.resolve(strict=True)` then allowlist containment; re-validated when the job starts; Gitleaks does not follow symlinks | `test_security.py`, `test_api.py`, E2E out-of-root test |
| Shell injection from file names / refs | argv lists only (`shell=False`); Git refs syntax-checked, resolved to a SHA, never passed raw to `git log` | `test_scanner.py::test_malicious_or_unknown_ref_rejected` |
| Repository code execution | No installs/tests run; `--no-ext-diff --no-textconv` for history; `core.fsmonitor=false`; no auto-loaded `.env`; scanner path never taken from the target | `test_scanner.py::test_gitleaks_invocation_is_hardened` |
| Scanner hangs / huge input | Deadline with process-tree kill, cancellation, `--max-target-megabytes`, `MAX_REPO_MB`/`MAX_REPO_FILES` pre-check, single worker by default | timeout/cancel/size tests |
| Gate bypass from inside the change | `--ignore-gitleaks-allow`; repo `.gitleaks.toml` ignored (explicit `--config`); repo `.gitleaksignore` (always read by Gitleaks) reported as a **blocking finding**; CI policy read from the base commit | `test_repo_gitleaksignore_and_config_are_not_honoured`, `test_inline_allow_comment_cannot_bypass` |
| CI secret theft via fork PR | `pull_request` event only, `contents: read`, `persist-credentials: false`, no secrets referenced | workflow review, `actionlint` |
| Dependency / supply chain | Actions pinned by commit SHA; Gitleaks download SHA-256 verified; gate dependency (PyYAML) installed with `--require-hashes`; npm lockfiles with `npm ci` | `secret-scan.yml`, `install_gitleaks.sh` |
| Dashboard exposed publicly | Loopback bind; refuses non-loopback without `ALLOW_REMOTE=true` **and** `API_TOKEN`; rate limiting in remote mode | `test_api.py::test_refuses_remote_bind_without_auth` |
| DNS rebinding / CSRF against loopback API | TrustedHost middleware; Origin allowlist on writes; JSON-only bodies; no cookies | `test_api.py::test_csrf_protections`, `test_dns_rebinding_host_rejected` |
| Formula injection in CSV exports | Leading `= + - @` neutralised | `test_csv_neutralises_formula_injection` |
| Forged scan attestation | EIP-191 signature, explicit `TRUSTED_ATTESTATION_SIGNERS`, chain binding, registry publisher match | `test_attestation.py`, `test_chain_interop.py` |
| Guessable hash anchored on chain | Only scan-level metadata is digested; commit replaced by a salted commitment; never secret-derived fingerprints | `test_payload_is_non_sensitive_and_canonical` |

## Residual risks (accepted, documented)

- **Default Gitleaks path allowlist.** Files under paths such as `node_modules/`,
  lock files and images are skipped by the Gitleaks defaults. A pull request
  adding such paths deserves human review.
- **Gate maintainers.** Anyone who can merge changes to the workflow, `rules/`
  or `.secretsentinel.yml`, or bypass branch rules, can weaken enforcement.
  Protect these paths with CODEOWNERS and rulesets.
- **Metadata sensitivity.** Paths, line numbers and commit IDs are stored and
  exported. Treat the database and reports as sensitive project metadata.
- **Local compromise.** A compromised user account, OS, Python environment or
  Gitleaks binary is out of scope.
- **Detection limits.** Regex/entropy scanning has false negatives; a clean
  result is "no matching secrets detected in the scanned scope", never "secure".

## Incident response embedded in the product (PRD 16.4)

Every finding links to remediation keyed by family: revoke/rotate → audit usage
→ contain → remove from current files → assess history/forks/caches → document
→ rescan. Signing keys and mnemonics are treated as compromised and require
migration to a new wallet. History rewriting alone never invalidates a
credential. SecretSentinel never uses, validates or moves anything with a
detected credential (invariant S5).
