# SecretSentinel Scanner

Find leaked secrets in current files and Git history before they reach a
pull request: application credentials and Web3 signing keys, seed phrases and
RPC keys. Built on [Gitleaks](https://github.com/gitleaks/gitleaks), with
reviewed exceptions and a fail-closed CI check. Secret values are never printed
or stored.

```bash
pip install secretsentinel-scanner
```

The command is `secretsentinel`. It needs Python 3.11+ and Gitleaks 8.x, either
on PATH or set in `GITLEAKS_PATH`.

```bash
secretsentinel doctor
```

```bash
secretsentinel check .
```

`check` scans current files and history and exits 1 on blocking findings (0 pass,
2 invalid input or policy, 3 scanner error), so it can fail a CI job.

## Before each commit

With the [pre-commit](https://pre-commit.com) framework:

```yaml
repos:
  - repo: https://github.com/SaIdEeVaN/secretsentinel
    rev: v1.0.0
    hooks:
      - id: secretsentinel
```

Or without it: `secretsentinel hook install /path/to/repo`.

## In GitHub Actions

```yaml
- uses: actions/checkout@v7
  with:
    fetch-depth: 0
- uses: SaIdEeVaN/secretsentinel@v1
```

## What it never does

It never uses, validates or sends a detected credential anywhere, and never runs
code from a scanned repository. Reports contain the rule, file, line and commit,
never the value. A clean scan is not proof that a repository has no secrets.

Documentation, the web dashboard and the rule audit:
https://github.com/SaIdEeVaN/secretsentinel
