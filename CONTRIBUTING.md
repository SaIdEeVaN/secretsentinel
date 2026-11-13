# Contributing

Bug reports, rule improvements and fixes are welcome. For security problems,
follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Set up

- Windows 11: `./scripts/bootstrap_windows.ps1` (see the README).
- Linux and macOS: `bash scripts/bootstrap_unix.sh`.

The detection tests need a real Gitleaks executable: set `GITLEAKS_PATH` or put
it on PATH. Tests that need it are skipped otherwise.

## Run the checks

```bash
python -m pytest backend/tests
```

```bash
cd frontend && npm test
```

```bash
cd frontend && npm run test:e2e
```

## Test data: never a real secret

- Never commit a real or real-looking secret, not even an expired one.
- Positive fixtures are templates (`rules/fixtures/synthetic_positive/*.tmpl`).
  Their values are generated at test time by `secretsentinel.fixtures.synth`,
  and the tests check that none of them leak into any output.
- In new tests, generate values with `synth(kind, label)` instead of writing them
  out.

## Changing detection rules

- Custom rules live in `rules/web3_rules.toml`. Gitleaks uses Go's RE2 regular
  expressions, so there is no look-around and no back-references.
- Every custom rule needs an entry in `rules/severity_mapping.yaml`.
- Rule IDs must not contain `generic`.
- Add a synthetic positive and a benign negative fixture, then run the near-miss
  audit (see [docs/RULE_AUDIT.md](docs/RULE_AUDIT.md)):

```bash
python scripts/audit_rules.py --config rules/web3_rules.toml --gitleaks "$(command -v gitleaks)"
```

## Pull requests

- One change per pull request, with tests.
- CI must pass: backend and frontend tests, the secret scan of this repository,
  and the package check (the built wheel installs and finds its rules).
