# Security model and limits

This is a local personal-development MVP. Keep it on loopback and scan only
repositories you are authorized to inspect. The dashboard is not a public
arbitrary-path scanning service.

## Boundaries

- The API canonicalizes paths and checks explicit scan roots, including symlink
  escapes. The CLI requires an explicitly supplied local target.
- Repository code is data, never executed during scanning. Git external diffs,
  text conversion and filesystem-monitor hooks are disabled for scanning.
- Gitleaks runs under a deadline with a controlled ruleset and redaction. Inline
  `gitleaks:allow` comments and target-controlled ignore files cannot silently
  disable the gate. Exclusions/suppressions belong in the reviewed policy.
- The sanitizer admits only known metadata. Raw `Secret`, `Match`, source lines,
  authors, commit messages and unexpected scanner fields never enter persistence
  or exported reports. Finding IDs are location-derived, not secret hashes.
- The API limits origins, hosts and request content types. Responses use safe
  errors, security headers and no-store caching. The built dashboard uses a CSP.
- No wallet or discovered token is contacted, validated against live services,
  used for signing, or sent on-chain. Test fixtures are generated at runtime from
  public synthetic labels, not committed as live-looking credential values.

## Incident response

Treat a real exposed token as compromised: revoke/rotate it at its issuer,
remove it from source and history as appropriate, and review access logs. For a
wallet signing secret, independently move assets to a newly created wallet and
revoke approvals as appropriate. Never send the value to this project's issue
tracker. Deleting a current line cannot revoke a credential or erase Git history.

## Limitations

Pattern matching has false positives and false negatives. Severity and confidence
are risk estimates, not proof of ownership or of a valid wallet. Public addresses,
transaction hashes and public RPC URLs are not automatically sensitive.

Sanitized reports still reveal repository names, relative paths, line numbers and
commit IDs. Protect the database and exported reports as project metadata. The
application does not encrypt SQLite or defend against a compromised local user,
OS, trusted executable, package registry or administrator.

Large files, exclusions, bounded scan scope, timeouts and incomplete Git history
can limit coverage. Failed/cancelled scans convey unknown security status.
Triaging a finding does not make a detected credential safe.

Remote operation needs reviewed authentication, TLS, authorization, deployment
isolation and data management. Optional bearer-token/ingestion hooks are not a
claim that the MVP is ready for multi-user production. Optional attestation
modules are disabled and have no deployed-contract or Sepolia validation claim.
