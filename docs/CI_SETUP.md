# GitHub Actions and required checks

The `secret-scan` job in `secret-scan.yml` is the merge gate. Backend, frontend
and real-browser jobs provide additional validation. The gate uses a reviewed
base-commit scanner and policy on pull requests; code under review is scanned
as data. It never runs scanned repository scripts or receives deployment secrets.

## Enable merge protection

1. Put the scanner, `rules/`, policy and workflows on the branch you intend to
   protect. If they are absent from the base commit the gate fails closed.
2. Open a test pull request into that branch so GitHub registers the
   `secret-scan` status check. The workflow supports any PR target branch.
3. In **Settings → Rules → Rulesets**, create an active branch ruleset for your
   default/protected branch (or use branch protection rules).
4. Require a pull request and **Require status checks to pass before merging**.
   Select the exact job/check `secret-scan` shown by the test run. Consider
   requiring backend, frontend and browser checks too.
5. Require branches to be up to date and protect changes to `.github/workflows/`,
   `.secretsentinel.yml`, the scanner and `rules/` with maintainer review. Configure
   required code-owner review for your team if you use CODEOWNERS.
6. Check bypass permissions and test with a contributor account that cannot
   bypass the rule. A failing status alone does not prevent a maintainer bypass.

These settings require repository administration and are not enabled by committing
a workflow. Do not claim protected merging until the checks below have actually
been exercised on GitHub.

## Verify the gate

Use a disposable test repository or branch and synthetic fixtures only:

- A documentation-only PR must pass.
- A PR adding a synthetic signing-key assignment must fail `secret-scan` with
  a redacted annotation. GitHub must refuse merging under the ruleset.
- Removing the exposure from the current tree is insufficient if a scanned
  commit still contains it. Rewrite the disposable PR's leaked history or use
  a different clean fixture PR; follow your incident process for real leaks.
- An invalid ruleset, policy, missing scanner or timeout must fail, never pass.
- A fork PR must run without repository secrets or write permissions. GitHub may
  require a maintainer to approve a first-time contributor's workflow run.
- Inspect logs and confirm that no synthetic fixture values appear.

Run `scripts/ci_gate_selftest.sh` locally for the same clean/findings/PR-range/
error/redaction exit-code checks before opening the test PR.

## Scope and trust

PR scans cover commits after the base SHA. Pushes to `main` and `codex/**` scan
commits after the previous push when it is available. Manual and weekly scheduled
runs cover working tree plus full history; schedules execute on GitHub's default
branch. Reviewed baselines cover accepted pre-existing findings and expire.

The gate loads policy, scanner and pinned PyYAML from the trusted base commit,
not the PR checkout. It will not fall back to running an untrusted PR scanner.
The checked-in workflow still needs protected review: contributors able to
change the gate or bypass branch rules can weaken enforcement.

Workflow permissions are `contents: read`, checkout credentials are not retained,
Gitleaks is downloaded with SHA-256 verification, and the gate uses no artifact
upload. Reports include file locations and commit IDs, so treat even sanitized
reports as potentially sensitive metadata.
