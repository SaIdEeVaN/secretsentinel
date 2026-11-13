# Security policy

## Reporting a vulnerability

Please report security problems in SecretSentinel **privately**, through GitHub:
open the repository's **Security** tab and choose **Report a vulnerability**.
Don't open a public issue, and don't include a working secret in the report.

This also applies if you found a leaked credential with SecretSentinel in
someone else's repository: tell that repository's owner privately (their
`SECURITY.md` or private reporting), not in a public issue or pull request,
because a public post spreads the credential further.

## Supported versions

Fixes go into the latest release on PyPI (`secretsentinel-scanner`) and the
`main` branch.

## Security model

What SecretSentinel stores, what it never does with a detected value, and its
known limits are described in [docs/SECURITY.md](docs/SECURITY.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
