import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api/client.js";
import ScanStatus from "../components/ScanStatus.jsx";
import { ErrorState, Loading } from "../components/States.jsx";
import { Field, PageHeader } from "../components/Widgets.jsx";
import { useAsync, usePolling } from "../hooks/useAsync.js";

const MODES = [
  {
    value: "both",
    title: "Directory + Git history",
    text: "Recommended. Covers uncommitted files and secrets that were committed and later deleted.",
  },
  { value: "dir", title: "Directory", text: "Current file contents, including uncommitted changes. Cannot see deleted history." },
  { value: "git", title: "Git history", text: "Every commit in scope. May miss untracked working-tree changes." },
];

function RegisterForm({ roots, onRegistered }) {
  const [path, setPath] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const repo = await api.registerRepository(path.trim(), name.trim());
      setPath("");
      setName("");
      onRegistered(repo);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="space-y-3" aria-label="Register a local folder">
      <Field
        label="Local folder path"
        htmlFor="reg-path"
        hint={
          roots.length
            ? `Must be inside an allowed root: ${roots.join(", ")}`
            : "No scan roots are allowed yet. Set SCAN_ROOT_ALLOWLIST and restart the backend."
        }
      >
        <input
          id="reg-path"
          className="input mono"
          value={path}
          onChange={(e) => setPath(e.target.value)}
          placeholder={roots[0] ? `${roots[0]}/my-project` : "C:\\Users\\you\\projects\\my-dapp"}
          required
          autoComplete="off"
          spellCheck={false}
        />
      </Field>
      <Field label="Display name (optional)" htmlFor="reg-name">
        <input id="reg-name" className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={200} />
      </Field>
      <button className="btn btn-ghost" type="submit" disabled={busy || !path.trim()}>
        {busy ? "Registering…" : "Register folder"}
      </button>
      <ErrorState error={error} />
    </form>
  );
}

export default function NewScan() {
  const [params] = useSearchParams();
  const repos = useAsync(() => api.repositories(), []);
  const status = useAsync(() => api.systemStatus(), []);
  const [repoId, setRepoId] = useState(params.get("repository") || "");
  const [mode, setMode] = useState("both");
  const [sinceRef, setSinceRef] = useState("");
  const [failOn, setFailOn] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [scan, setScan] = useState(null);
  const inFlight = useRef(false);

  const allowed = useMemo(() => (repos.data ?? []).filter((r) => r.allowed), [repos.data]);
  useEffect(() => {
    if (!repoId && allowed.length) setRepoId(allowed[0].id);
  }, [allowed, repoId]);

  const running = scan && (scan.status === "queued" || scan.status === "running");
  usePolling(
    async () => {
      try {
        setScan(await api.scan(scan.id));
      } catch (e) {
        setError(e);
      }
    },
    1200,
    Boolean(running),
  );

  const start = async (e) => {
    e.preventDefault();
    if (inFlight.current || running) return; // prevent duplicate requests
    inFlight.current = true;
    setSubmitting(true);
    setError(null);
    try {
      const body = { repository_id: repoId, mode };
      if (sinceRef.trim() && mode !== "dir") body.since_ref = sinceRef.trim();
      if (failOn) body.fail_on = failOn;
      const res = await api.startScan(body);
      setScan({ id: res.scan_id, status: res.status });
    } catch (err) {
      setError(err);
    } finally {
      inFlight.current = false;
      setSubmitting(false);
    }
  };

  const cancel = async () => {
    try {
      setScan(await api.cancelScan(scan.id));
    } catch (e) {
      setError(e);
    }
  };

  const roots = status.data?.allowed_roots ?? [];
  const scannerMissing = status.data && !status.data.scanner.available;

  return (
    <>
      <PageHeader title="New Scan" subtitle="Scans run locally against an explicitly registered, allowlisted folder. Repository code is never executed." />
      {scannerMissing && (
        <div role="alert" className="card mb-4 border-warn/60 bg-warn-bg p-4 text-sm">
          <strong className="text-warn">Gitleaks not available.</strong> {status.data.scanner.message} Scans will fail closed until it is
          installed.
        </div>
      )}
      <div className="grid gap-5 lg:grid-cols-[1.4fr_1fr]">
        <form onSubmit={start} className="card space-y-5 p-5" aria-label="Start a scan">
          {repos.loading && !repos.data && <Loading label="Loading repositories…" />}
          <ErrorState error={repos.error} onRetry={repos.reload} />
          <Field label="Repository" htmlFor="repo" hint={allowed.length ? null : "Register a folder first (right)."}>
            <select id="repo" className="input" value={repoId} onChange={(e) => setRepoId(e.target.value)} required>
              <option value="" disabled>
                Select a repository
              </option>
              {(repos.data ?? []).map((r) => (
                <option key={r.id} value={r.id} disabled={!r.allowed}>
                  {r.display_name}
                  {r.allowed ? "" : " (outside allowed roots)"}
                </option>
              ))}
            </select>
          </Field>

          <fieldset>
            <legend className="label">Scan mode</legend>
            <div className="grid gap-2 sm:grid-cols-3">
              {MODES.map((m) => (
                <label
                  key={m.value}
                  className={`card cursor-pointer p-3 text-sm focus-within:outline-2 focus-within:outline-[var(--focus)] ${mode === m.value ? "border-accent ring-1 ring-accent" : ""}`}
                >
                  <input type="radio" name="mode" value={m.value} checked={mode === m.value} onChange={() => setMode(m.value)} className="sr-only" />
                  <span className="font-semibold">
                    {mode === m.value ? "◉ " : "○ "}
                    {m.title}
                  </span>
                  <span className="mt-1 block text-xs text-muted">{m.text}</span>
                </label>
              ))}
            </div>
          </fieldset>

          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Only commits after (optional)" htmlFor="since" hint="Branch, tag or SHA. Git/both modes only.">
              <input
                id="since"
                className="input mono"
                value={sinceRef}
                onChange={(e) => setSinceRef(e.target.value)}
                disabled={mode === "dir"}
                placeholder="origin/main"
                maxLength={200}
                spellCheck={false}
              />
            </Field>
            <Field label="Block at severity" htmlFor="failon" hint="Default: repository policy file, then server default.">
              <select id="failon" className="input" value={failOn} onChange={(e) => setFailOn(e.target.value)}>
                <option value="">Default ({status.data?.default_fail_on ?? "high"})</option>
                <option value="critical">Critical only</option>
                <option value="high">High and above</option>
                <option value="medium">Medium and above</option>
                <option value="low">Everything</option>
                <option value="none">Never block (report only)</option>
              </select>
            </Field>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button type="submit" className="btn btn-primary" disabled={!repoId || submitting || running}>
              {submitting ? "Starting…" : running ? "Scan in progress…" : "Start scan"}
            </button>
            {running && (
              <button type="button" className="btn btn-danger" onClick={cancel}>
                Cancel scan
              </button>
            )}
          </div>
          <ErrorState error={error} />
          {scan && (
            <div className="space-y-3">
              <ScanStatus scan={scan} />
              {!running && (
                <Link to={`/scans/${scan.id}`} className="btn btn-ghost">
                  View scan details & findings →
                </Link>
              )}
            </div>
          )}
        </form>

        <section className="card p-5" aria-labelledby="reg-h">
          <h2 id="reg-h" className="mb-3 font-semibold">
            Register a folder
          </h2>
          <RegisterForm
            roots={roots}
            onRegistered={(repo) => {
              repos.reload();
              setRepoId(repo.id);
            }}
          />
          <p className="mt-4 text-xs text-muted">
            Only folders inside <span className="mono">SCAN_ROOT_ALLOWLIST</span> can be registered or scanned. Paths are canonicalised
            and symlink escapes are rejected. Remote URLs are never cloned.
          </p>
        </section>
      </div>
    </>
  );
}
