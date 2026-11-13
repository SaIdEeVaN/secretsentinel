# Changelog

## 1.0.0

First release on PyPI as `secretsentinel-scanner` (the command is `secretsentinel`).

### What's included

- **Scanner and CLI** built on Gitleaks 8.30.1: scan current files, Git history,
  or both (`scan`, `check`), with exit codes for CI (0 pass, 1 blocking
  findings, 2 invalid input or policy, 3 scanner error). Secret values are never
  printed or stored.
- **Rules:** the Gitleaks defaults plus 18 Web3 rules (signing keys, mnemonics,
  RPC and provider keys, keystores) and 2 rules that fill gaps in the defaults:
  Twitter/X bearer tokens with a 21-character `A` prefix, and credentials in URL
  query strings.
- **Policy:** severity threshold, path exclusions and reviewed, expiring
  suppressions in `.secretsentinel.yml`; reviewed baselines.
- **Pre-commit hook** for staged changes (`secretsentinel hook install`, or the
  pre-commit framework hook `id: secretsentinel`).
- **GitHub Action** (`uses: SaIdEeVaN/secretsentinel@v1`) with annotations and a
  job summary.
- **Dashboard** (from a checkout or self-hosted): history, filters, triage,
  suppressions, audit trail, CI checks, JSON/CSV/SARIF export, and alerts for new
  blocking findings when fed by GitHub Actions.
- **Rule audit script** (`scripts/audit_rules.py`) that looks for near-miss gaps.

### Known limits

- A clean scan is not proof that a repository has no secrets.
- About 150 Gitleaks default rules miss an unquoted value followed directly by
  `&`, `,`, `)`, `]` or `}` (see `docs/RULE_AUDIT.md`).
- The GitHub Action runs on Linux x64 runners only.
- The hosted dashboard serves one owner with one shared sign-in token.
- Windows CI is still marked experimental.
