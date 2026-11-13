# Hosted dashboard on Render + Neon

A private web dashboard that shows scan results for your GitHub repositories.
**The server never scans or clones code.** GitHub Actions scans each repository
and uploads only the sanitized report.

```text
GitHub Actions (your repo)                      Render                                 Neon
┌──────────────────────────────┐   HTTPS POST   ┌──────────────────────────────┐  TLS  ┌──────────────┐
│ dashboard-upload.yml         │ ─────────────▶ │ secretsentinel-dashboard     │──────▶│ Postgres     │
│  scan main (tree + history)  │  INGEST_TOKEN  │  FastAPI API + React UI      │ DB_URL│ (Neon)       │
│  upload_report.py            │                │  sign-in with API_TOKEN      │       └──────────────┘
└──────────────────────────────┘                └──────────────────────────────┘
```

What leaves CI: repository name, rule IDs, severities, relative file paths, line
numbers, commit SHAs and counts. Never secret values, matched text or source
lines (the ingest endpoint rejects any report that is not the strict
`secretsentinel-report/v1` schema).

## Plans and limits

Both use free plans:

- **Render web service (free):** sleeps after 15 minutes without traffic; the
  next visit or upload takes about a minute to wake it. The upload script
  retries for that.
- **Neon Postgres (free):** does not expire. Storage is small (0.5 GB per
  project at the time of writing), which is plenty: the dashboard stores only
  rule IDs, locations and counts. The compute scales to zero when idle and
  resumes on the next query in under a second; the app reconnects
  automatically (`pool_pre_ping`).

## 0. Create the Neon database (once)

In the [Neon console](https://console.neon.tech):

1. **New project**, region close to the Render service (the Blueprint uses
   Render's `singapore` region, so `AWS Asia Pacific (Singapore)`).
2. **Roles → New role** `secretsentinel_app`. Don't use the `neondb_owner`
   role: the app needs no superuser rights.
3. **Databases → New database** `secretsentinel`, owner `secretsentinel_app`.
   Owning the database lets the app create its own tables on first start;
   no migration step is needed.
4. **Connect** → database `secretsentinel`, role `secretsentinel_app` → copy
   the connection string. Either the direct or the pooled (`-pooler`) host
   works; keep `sslmode=require`.

The string looks like
`postgresql://secretsentinel_app:<password>@ep-xxx.<region>.aws.neon.tech/secretsentinel?sslmode=require&channel_binding=require`.
It contains the password: paste it only into Render, never into the
repository, an issue or a chat.

## 1. Deploy (once)

Render dashboard → **New → Blueprint** → choose this repository. Render
reads `render.yaml` and asks for `DB_URL`: paste the Neon connection string,
then **Apply**. It creates the web service and builds the dashboard; the app
creates its tables in Neon on first start. Pushes to `main` redeploy
automatically, and Blueprint syncs never overwrite `DB_URL`.

The web service gets these settings from the Blueprint:

| Variable | Purpose |
|---|---|
| `API_TOKEN` | Generated. Sign-in token for the dashboard. |
| `INGEST_TOKEN` | Generated. Used only by CI to upload reports. Cannot read the dashboard. |
| `DB_URL` | The Neon connection string (entered by you; `sync: false`). |
| `HOST=0.0.0.0`, `ALLOW_REMOTE=true`, `APP_ENV=production` | Remote mode; the server refuses to start remotely without `API_TOKEN`. |

`SCAN_ROOT_ALLOWLIST` is deliberately unset, so the hosted copy can't scan its
own disk. Render's public hostname is trusted automatically; for a custom
domain, add `TRUSTED_HOSTS=your.domain`.

## 2. Sign in

Render dashboard → `secretsentinel-dashboard` → **Environment** → reveal
`API_TOKEN`. Open the service URL and paste it. The token stays in that browser
tab only and is cleared when the tab closes.

## Using the dashboard

- **Overview** opens with one line for all repositories (for example "1 of 23
  repositories have blocking findings in their latest scan") and links to the
  ones that need attention, then counts, severity, recent scans and findings.
- **Findings**: severity and status chips show how many findings each choice
  would return. Tick findings (or "select all" on the page) to mark them Open,
  Acknowledged or Resolved together; each change is recorded in the audit
  trail. On wide screens a finding opens in a side panel with its location,
  triage control, recommended response, audit trail and, if suppressed, the
  suppression's reason, reviewer and expiry.
- **Scan History** lists every run with result chips and repository, mode and
  status filters. **CI Checks** shows each repository's latest uploads from
  GitHub Actions with a sanitized log made from stored metadata only.
- **Rules & Policy** shows which severities block, warn or only inform under
  the current threshold, the mapped rules, and dashboard suppressions.
- **Settings** groups the server status (scanner, scanning mode, access,
  attestations) and lists repositories, which you can remove.

### Exceptions for repositories scanned by GitHub Actions

There are two places for a reviewed exception, and both stick:

- **On the dashboard.** Suppress a finding from its detail panel. Every later
  GitHub Actions upload for that repository applies the suppression, so the
  finding stays suppressed and does not raise the new-finding alert. It covers
  the same rule and path (and the same line, or the same commit if the line
  moved), stops at its expiry, and applies only to that repository.
  Deactivate it in **Rules & Policy** and the next upload reports the finding
  again. The upload's scan shows a note that dashboard suppressions were
  applied: the repository's own CI gate (if it has one) does not see them.
- **In the repository.** Put the exception in **that repository's**
  `.secretsentinel.yml`; the scan reads it on every run, and it travels with
  the code. Prefer this for repositories you own. Example (each entry needs a
  rule, a path, a reason, a reviewer and an expiry within a year):

```yaml
version: 1
suppressions:
  - id: EX-001
    rule_id: mapbox-api-token
    path: examples/app/settings.env
    reason: Public (pk.) token that the example ships to the browser by design.
    reviewer: your-name
    expires: 2027-05-12
```

## 3. Connect repositories

### Option A: central list (recommended)

This repository can scan a whole list of repositories for you, so the other
repositories need no files or settings of their own:

1. Do the one-time setup below (environment, secret, variable) in **this**
   repository only.
2. Add `owner/name` lines to [`.github/dashboard-repos.txt`](../.github/dashboard-repos.txt)
   and push to `main`.

`dashboard-fleet.yml` then scans every listed repository (working tree and
full history) on that push, every day (05:23 UTC), and whenever you run **Actions →
Scan repository list for SecretSentinel dashboard → Run workflow**. Each
repository is its own job, so one failing repository doesn't stop the others.
The scanner only reads the listed repositories; it never runs their code. A
`.secretsentinel.yml` in a listed repository is used as its policy.

**Private repositories** also need a token that can read them: create a
fine-grained personal access token (GitHub → Settings → Developer settings)
limited to those repositories with *Contents: Read-only*, and save it in this
repository as the Actions secret `SECRETSENTINEL_REPO_READ_TOKEN`. Public
repositories don't need it.

Fine-grained tokens expire. The workflow's **read token expiry** job checks the
expiry date GitHub reports for this token: it adds a warning 14 days before,
and fails (so GitHub emails you about the failed run) 7 days before or once
GitHub rejects the token. The scans still run either way. To renew, create a
new token with the same settings and update the secret.

### Option B: a workflow in each repository

This repository already contains everything. For **another** repository, copy:

- `.github/workflows/dashboard-upload.yml`
- `backend/`, `rules/`, `scripts/install_gitleaks.sh`, `scripts/upload_report.py`
- optionally `.secretsentinel.yml` (policy: fail threshold, reviewed suppressions)

Then, in that repository on GitHub:

1. **Settings → Environments → New environment** named
   `secretsentinel-dashboard`. Under *Deployment branches*, allow only `main`,
   so no other branch or pull request can use the upload token.
2. In that environment, add the secret **`SECRETSENTINEL_INGEST_TOKEN`** with
   the value of `INGEST_TOKEN` from Render.
3. **Settings → Secrets and variables → Actions → Variables**: add
   **`SECRETSENTINEL_DASHBOARD_URL`** = the service URL, e.g.
   `https://secretsentinel-dashboard.onrender.com`.
4. **Actions → Upload scan to SecretSentinel dashboard → Run workflow** (or push
   to `main`). It also runs weekly. The scan appears in the dashboard.

The workflow is skipped while the variable is unset, and it never runs for pull
requests. Merge blocking stays with `secret-scan.yml` (see [CI_SETUP.md](CI_SETUP.md)).

## Alerts: new blocking findings

The scan workflows upload with `--fail-on-new-blocking`. When a repository has
blocking findings it **never had before**, that repository's job fails, so
GitHub's own "workflow run failed" email is the alert. Known findings that are
still present do not fail it again; check those on the dashboard.

- Make sure the email is on: GitHub → your avatar → Settings → Notifications,
  the **Actions** section: email for failed workflow runs. For the scheduled
  run, GitHub notifies the person who last changed the schedule line.
- The alert is deliberately not a GitHub issue: issues and run logs of a
  public repository are public, and a list of file locations would point
  others at possibly real secrets. Logs show counts only; details stay on the
  signed-in dashboard.
- "New" compares fingerprints with everything the dashboard already stored for
  that repository, so the first scan of a newly listed repository alerts once
  for whatever it finds.

## Scan history retention

`render.yaml` sets `SCAN_RETENTION_DAYS=180`: when the service starts (it
restarts after every idle period on the free plan), scans older than 180 days
are deleted with their findings. Never deleted, whatever their age:

- each repository's most recent completed scan (the dashboard's current state),
- scans with an attestation (signed evidence),
- scans still queued or running.

Set it to `0` to keep everything. To prune by hand:
`secretsentinel db prune --days 180` with `DB_URL` pointing at the database.

## Rotating tokens

Render → Environment → edit `API_TOKEN` or `INGEST_TOKEN` (use a long random
value, e.g. `python -c "import secrets; print(secrets.token_urlsafe(32))"`) →
Save (the service restarts). Update the GitHub secret after changing
`INGEST_TOKEN`.

To rotate the **database password**: Neon console → Roles →
`secretsentinel_app` → Reset password → copy the new connection string →
Render → Environment → `DB_URL` → Save. The service restarts with the new
password; the old one stops working immediately, so do both steps together.

## Security notes

- One shared `API_TOKEN` gives full dashboard access (triage, suppressions,
  deleting repositories). There are no per-user accounts; share it only with
  people who should have that access.
- The database is reachable from the internet but only over TLS and with the
  `secretsentinel_app` password; that role is not a superuser and can't create
  roles or other databases. Neon's paid plans add an IP allowlist if you want
  to restrict connections further. Neon also keeps point-in-time history, so
  an accidental delete can be restored from the console.
- Remote mode enables HSTS and rate limiting, disables the OpenAPI docs, and
  keeps the loopback defaults (Host check, Origin check, JSON-only writes).
- Rate limiting is per client address as seen by the server; behind Render's
  proxy that is effectively one shared budget (300 requests/minute by default).

## Troubleshooting

| Symptom | Fix |
|---|---|
| Upload fails with `401 UNAUTHORIZED` | `SECRETSENTINEL_INGEST_TOKEN` doesn't match Render's `INGEST_TOKEN`. |
| A repository's job fails at checkout with `Repository not found` | It is private (or misspelled): set `SECRETSENTINEL_REPO_READ_TOKEN` or fix the line in `dashboard-repos.txt`. |
| Upload fails with `404` | `INGEST_TOKEN` is not set on the service. |
| Upload gives up after retries | The service may be suspended or failing; check its Render logs. |
| Dashboard says the token was not accepted | Copy `API_TOKEN` again (not `INGEST_TOKEN`). |
| `400 Invalid host header` on a custom domain | Add the domain to `TRUSTED_HOSTS`. |
| Build fails at `npm run build` with a Node version error | Set `NODE_VERSION` to a current LTS (22 or newer) on the service. |
| Deploy fails with `password authentication failed` | `DB_URL` is wrong or the Neon password was reset; copy the connection string again. |
| Deploy fails with `permission denied for schema public` | The role in `DB_URL` doesn't own the `secretsentinel` database; make it the owner (step 0.3). |
| First request after a long idle period is slow | Both Render and Neon were asleep; later requests are fast. |
