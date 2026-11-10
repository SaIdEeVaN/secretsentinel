# Hosted dashboard on Render

A private web dashboard that shows scan results for your GitHub repositories.
**The server never scans or clones code.** GitHub Actions scans each repository
and uploads only the sanitized report.

```text
GitHub Actions (your repo)                      Render
┌──────────────────────────────┐   HTTPS POST   ┌──────────────────────────────┐   ┌──────────────┐
│ dashboard-upload.yml         │ ─────────────▶ │ secretsentinel-dashboard     │──▶│ Postgres     │
│  scan main (tree + history)  │  INGEST_TOKEN  │  FastAPI API + React UI      │   │ (private)    │
│  upload_report.py            │                │  sign-in with API_TOKEN      │   └──────────────┘
└──────────────────────────────┘                └──────────────────────────────┘
```

What leaves CI: repository name, rule IDs, severities, relative file paths, line
numbers, commit SHAs and counts. Never secret values, matched text or source
lines (the ingest endpoint rejects any report that is not the strict
`secretsentinel-report/v1` schema).

## Plans and limits

`render.yaml` uses free plans:

- **Web service (free):** sleeps after 15 minutes without traffic; the next visit
  or upload takes about a minute to wake it. The upload script retries for that.
- **Postgres (free):** 1 GB, and **Render deletes it 30 days after creation**
  (14-day grace period) unless you upgrade it. Upgrading keeps the data: Render
  dashboard → `secretsentinel-db` → Upgrade.

## 1. Deploy (once)

Render dashboard → **New → Blueprint** → choose this repository → **Apply**.
Render reads `render.yaml`, creates the database and the web service, and
builds the dashboard. Pushes to `main` redeploy automatically.

The web service gets these settings from the Blueprint:

| Variable | Purpose |
|---|---|
| `API_TOKEN` | Generated. Sign-in token for the dashboard. |
| `INGEST_TOKEN` | Generated. Used only by CI to upload reports. Cannot read the dashboard. |
| `DB_URL` | The private Postgres connection string. |
| `HOST=0.0.0.0`, `ALLOW_REMOTE=true`, `APP_ENV=production` | Remote mode; the server refuses to start remotely without `API_TOKEN`. |

`SCAN_ROOT_ALLOWLIST` is deliberately unset, so the hosted copy can't scan its
own disk. Render's public hostname is trusted automatically; for a custom
domain, add `TRUSTED_HOSTS=your.domain`.

## 2. Sign in

Render dashboard → `secretsentinel-dashboard` → **Environment** → reveal
`API_TOKEN`. Open the service URL and paste it. The token stays in that browser
tab only and is cleared when the tab closes.

## 3. Connect a repository

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

## Rotating tokens

Render → Environment → edit `API_TOKEN` or `INGEST_TOKEN` (use a long random
value, e.g. `python -c "import secrets; print(secrets.token_urlsafe(32))"`) →
Save (the service restarts). Update the GitHub secret after changing
`INGEST_TOKEN`.

## Security notes

- One shared `API_TOKEN` gives full dashboard access (triage, suppressions,
  deleting repositories). There are no per-user accounts; share it only with
  people who should have that access.
- The database has an empty IP allowlist, so only Render services connect.
- Remote mode enables HSTS and rate limiting, disables the OpenAPI docs, and
  keeps the loopback defaults (Host check, Origin check, JSON-only writes).
- Rate limiting is per client address as seen by the server; behind Render's
  proxy that is effectively one shared budget (300 requests/minute by default).

## Troubleshooting

| Symptom | Fix |
|---|---|
| Upload fails with `401 UNAUTHORIZED` | `SECRETSENTINEL_INGEST_TOKEN` doesn't match Render's `INGEST_TOKEN`. |
| Upload fails with `404` | `INGEST_TOKEN` is not set on the service. |
| Upload gives up after retries | The service may be suspended or failing; check its Render logs. |
| Dashboard says the token was not accepted | Copy `API_TOKEN` again (not `INGEST_TOKEN`). |
| `400 Invalid host header` on a custom domain | Add the domain to `TRUSTED_HOSTS`. |
| Build fails at `npm run build` with a Node version error | Set `NODE_VERSION` to a current LTS (22 or newer) on the service. |
| History disappeared after a month | The free database expired; upgrade it before day 30 to keep data. |
