import { useState } from "react";
import { api, hasAuthToken, setAuthToken } from "../api/client.js";
import { EmptyState, ErrorState, Loading } from "../components/States.jsx";
import { Field, KeyValue, PageHeader } from "../components/Widgets.jsx";
import { formatDate, timeAgo } from "../components/format.js";
import { useAsync } from "../hooks/useAsync.js";
import { useSystem } from "../context/system.js";

function Ok({ ok, children }) {
  return (
    <span className={ok ? "text-ok" : "text-critical"}>
      <span aria-hidden="true">{ok ? "✓ " : "✕ "}</span>
      {children}
    </span>
  );
}

export default function Settings({ onAuthChanged }) {
  const status = useAsync(() => api.systemStatus(), []);
  const repos = useAsync(() => api.repositories(), []);
  const audit = useAsync(() => api.auditEvents({ limit: 25 }), []);
  const [token, setToken] = useState("");
  const [error, setError] = useState(null);
  const { signOut } = useSystem();
  const s = status.data;

  const remove = async (repo) => {
    if (!window.confirm(`Remove "${repo.display_name}" and all of its scan history from the local database? Files on disk are not touched.`)) return;
    setError(null);
    try {
      await api.deleteRepository(repo.id);
      repos.reload();
    } catch (e) {
      setError(e);
    }
  };

  return (
    <>
      <PageHeader title="Settings" subtitle="Local configuration is read from environment variables when the backend starts." />
      <div className="space-y-5">
        <section className="card p-4" aria-labelledby="sys-h">
          <h2 id="sys-h" className="mb-3 font-semibold">
            System status
          </h2>
          {status.loading && !s && <Loading />}
          <ErrorState error={status.error} onRetry={status.reload} />
          {s && (
            <KeyValue
              items={[
                ["SecretSentinel", <span className="mono">{s.version}</span>],
                [
                  "Gitleaks",
                  <Ok ok={s.scanner.available}>{s.scanner.available ? `v${s.scanner.version}` : s.scanner.message}</Ok>,
                ],
                ["Git", <Ok ok={s.git_available}>{s.git_available ? "available" : "not found (git/both modes unavailable)"}</Ok>],
                ["Ruleset", <span className="mono">{s.ruleset_version ?? "invalid"}</span>],
                ["Allowed scan roots", s.allowed_roots.length ? <span className="mono">{s.allowed_roots.join("; ")}</span> : "none (set SCAN_ROOT_ALLOWLIST)"],
                ["Default block threshold", s.default_fail_on],
                ["Scan timeout", `${s.timeout_seconds} s`],
                ["Max file size", `${s.max_file_mb} MB`],
                ["Concurrent scans", s.max_concurrent_scans],
                ["Environment", s.app_env],
                ["Mode", s.hosted ? "hosted (results uploaded from CI)" : "local"],
                ["CI uploads", s.ingest_enabled ? "enabled" : "disabled (set INGEST_TOKEN)"],
                ["API authentication", s.auth_required ? "required (remote mode)" : "not required (loopback only)"],
                ["Blockchain attestations", s.blockchain_enabled ? "enabled (Sepolia, optional)" : "disabled"],
              ]}
            />
          )}
        </section>

        {(s?.auth_required || hasAuthToken()) && (
          <section className="card p-4" aria-labelledby="auth-h">
            <h2 id="auth-h" className="font-semibold">
              API token
            </h2>
            <p className="mt-1 text-xs text-muted">Kept in memory for this tab only - never written to browser storage.</p>
            <form
              className="mt-3 flex flex-wrap items-end gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                setAuthToken(token);
                setToken("");
                onAuthChanged && onAuthChanged();
                status.reload();
                repos.reload();
              }}
            >
              <div className="min-w-60 flex-1">
                <Field label="Bearer token" htmlFor="tok">
                  <input id="tok" type="password" className="input" value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off" />
                </Field>
              </div>
              <button type="submit" className="btn btn-primary">
                Use token
              </button>
              {signOut && (
                <button type="button" className="btn btn-ghost" onClick={signOut}>
                  Sign out
                </button>
              )}
            </form>
          </section>
        )}

        <section className="card p-4" aria-labelledby="repos-h">
          <h2 id="repos-h" className="mb-3 font-semibold">
            Registered repositories
          </h2>
          <ErrorState error={error || repos.error} />
          {repos.data && repos.data.length === 0 && <EmptyState title="No repositories registered yet." />}
          {repos.data && repos.data.length > 0 && (
            <ul className="divide-y divide-line">
              {repos.data.map((r) => (
                <li key={r.id} className="flex flex-wrap items-center justify-between gap-3 py-2">
                  <div className="min-w-0">
                    <p className="font-medium">{r.display_name}</p>
                    <p className="mono text-xs text-muted">{r.local_path}</p>
                    <p className="text-xs text-muted">
                      {r.allowed ? "inside allowed roots" : "outside allowed roots - cannot be scanned from the dashboard"} · last scan{" "}
                      {timeAgo(r.last_scan_at)}
                    </p>
                  </div>
                  <button type="button" className="btn btn-danger text-xs" onClick={() => remove(r)}>
                    Remove
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="card p-4" aria-labelledby="audit-h">
          <h2 id="audit-h" className="mb-3 font-semibold">
            Audit log
          </h2>
          {audit.data && audit.data.length === 0 && <EmptyState title="No audit events yet." />}
          {audit.data && audit.data.length > 0 && (
            <ul className="space-y-1 text-sm">
              {audit.data.map((e) => (
                <li key={e.id} className="flex flex-wrap gap-x-3">
                  <span className="text-xs text-muted whitespace-nowrap">{formatDate(e.occurred_at)}</span>
                  <span className="mono text-xs">{e.action}</span>
                  <span className="text-xs text-muted">by {e.actor}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </>
  );
}
