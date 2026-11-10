# Demonstrating the MVP safely

Run the local backend and dashboard using the root README. Use generated demo
data throughout; never paste a real wallet phrase, private key or service token.

1. On **Overview**, select **Create demo repository**. It creates a new folder
   under the first allowed root and registers it locally.
2. On **New Scan**, keep **Directory + Git history**, start, and open the result.
   Expect a blocked result: a synthetic signing key exists only in old history,
   a synthetic mnemonic is untracked, and a provider token is in configuration.
3. Open a finding. Verify location, rule, severity, confidence and remediation.
   Acknowledge it: the status changes and an audit event is recorded, but the
   finding still blocks the policy.
4. Download JSON, CSV and SARIF from scan details. Each includes all safe
   metadata from the scan, independent of table pagination. There is no reveal
   control and no raw matched value in the report.
5. Filter findings by severity/status and open scan history. Use the phone layout
   or keyboard to navigate the same workflow.
6. For a fixed-leak demonstration, scan a separate disposable directory in
   directory mode, remove its synthetic fixture and rescan. The new scan passes;
   the historical finding shows it was not detected by the latest scan. The
   browser suite automates this without requiring manual creation of values.
7. See **Settings** for scanner readiness, allowed roots, repositories and audit
   events. Removing a registered repository deletes metadata, not local files.

The built-in Git demo intentionally remains blocked after deleting current files,
because old commits still contain the synthetic key. This demonstrates history
coverage; do not weaken the gate to make that demo pass.

For CI, run `scripts/ci_gate_selftest.sh` to exercise clean PR, leaking PR,
invalid-policy, missing-scanner and report-redaction behavior. Complete the
GitHub ruleset checks in [CI_SETUP.md](CI_SETUP.md) before claiming merge blocking.
