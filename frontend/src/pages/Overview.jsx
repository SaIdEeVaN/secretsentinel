import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client.js";
import FindingTable from "../components/FindingTable.jsx";
import { ResultPill } from "../components/ScanStatus.jsx";
import { EmptyState, ErrorState, Loading } from "../components/States.jsx";
import { PageHeader, SeverityBars, StatCard, TrendChart } from "../components/Widgets.jsx";
import { MODE_LABEL, timeAgo } from "../components/format.js";
import { useAsync } from "../hooks/useAsync.js";
import { localScanningEnabled, useSystem } from "../context/system.js";

function CiOnboarding() {
  return (
    <div className="card p-6">
      <h2 className="text-lg font-semibold">Waiting for the first scan upload</h2>
      <p className="mt-2 text-sm text-muted">
        This hosted dashboard does not scan code itself. GitHub Actions scans each repository and uploads only the
        redacted report here.
      </p>
      <ol className="mt-3 list-decimal space-y-2 pl-5 text-sm">
        <li>
          Add <span className="mono">.github/workflows/dashboard-upload.yml</span> to the repository (see{" "}
          <span className="mono">docs/HOSTING.md</span>).
        </li>
        <li>
          In the repository settings, add the variable <span className="mono">SECRETSENTINEL_DASHBOARD_URL</span> (this
          site's address) and the secret <span className="mono">SECRETSENTINEL_INGEST_TOKEN</span>.
        </li>
        <li>Push to the default branch or run the workflow manually. The scan appears here when it finishes.</li>
      </ol>
    </div>
  );
}

function Onboarding({ status, onDemo, demoBusy, demoError }) {
  const roots = status?.allowed_roots ?? [];
  return (
    <div className="card p-6">
      <h2 className="text-lg font-semibold">Get started</h2>
      <ol className="mt-3 list-decimal space-y-2 pl-5 text-sm">
        <li>
          {status?.scanner?.available ? (
            <>
              Gitleaks <span className="mono">{status.scanner.version}</span> detected.
            </>
          ) : (
            <>Install Gitleaks and set <span className="mono">GITLEAKS_PATH</span> (see the README).</>
          )}
        </li>
        <li>
          Allow the folders the dashboard may scan with <span className="mono">SCAN_ROOT_ALLOWLIST</span>
          {roots.length ? (
            <>
              {" "}
              (currently: <span className="mono">{roots.join(", ")}</span>).
            </>
          ) : (
            " (none configured yet)."
          )}
        </li>
        <li>
          Register a folder on <Link className="text-accent underline" to="/scan/new">New Scan</Link>, or create a synthetic demo
          repository to try it safely.
        </li>
      </ol>
      <div className="mt-4 flex flex-wrap gap-2">
        <button type="button" className="btn btn-primary" onClick={onDemo} disabled={demoBusy || !roots.length}>
          {demoBusy ? "Creating demo…" : "Create demo repository"}
        </button>
        <Link to="/scan/new" className="btn btn-ghost">
          Register a folder
        </Link>
      </div>
      <div className="mt-3">
        <ErrorState error={demoError} />
      </div>
    </div>
  );
}

export default function Overview() {
  const navigate = useNavigate();
  const { status: system } = useSystem();
  const local = localScanningEnabled(system);
  const metrics = useAsync(() => api.overview(), []);
  const status = useAsync(() => api.systemStatus(), []);
  const current = useAsync(() => api.findings({ page_size: 8 }), []);
  const [demoBusy, setDemoBusy] = useState(false);
  const [demoError, setDemoError] = useState(null);

  const createDemo = async () => {
    setDemoBusy(true);
    setDemoError(null);
    try {
      const res = await api.createDemo();
      navigate(`/scan/new?repository=${res.repository.id}`);
    } catch (e) {
      setDemoError(e);
    } finally {
      setDemoBusy(false);
    }
  };

  const m = metrics.data;
  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="Current state across each repository's most recent completed scan."
        actions={
          local ? (
            <Link to="/scan/new" className="btn btn-primary">
              ＋ New Scan
            </Link>
          ) : null
        }
      />
      {metrics.loading && !m && <Loading />}
      <ErrorState error={metrics.error} onRetry={metrics.reload} />
      {m && m.scans_total === 0 &&
        (local ? (
          <Onboarding status={status.data} onDemo={createDemo} demoBusy={demoBusy} demoError={demoError} />
        ) : (
          <CiOnboarding />
        ))}
      {m && m.scans_total > 0 && (
        <div className="space-y-5">
          <section aria-label="Summary" className="grid grid-cols-2 gap-3 lg:grid-cols-5">
            <StatCard label="Repositories" value={m.repositories} />
            <StatCard label="Completed scans" value={m.scans_completed} />
            <StatCard label="Open findings" value={m.open_findings} tone={m.open_findings ? "warn" : "ok"} />
            <StatCard
              label="Blocking now"
              value={m.blocking_open_findings}
              tone={m.blocking_open_findings ? "danger" : "ok"}
              hint="Would fail the policy gate"
            />
            <StatCard label="Failed scans" value={m.scans_failed} tone={m.scans_failed ? "warn" : undefined} hint="Status unknown" />
          </section>

          <div className="grid gap-5 lg:grid-cols-2">
            <section className="card p-4" aria-labelledby="sev-h">
              <h2 id="sev-h" className="mb-3 font-semibold">
                Open findings by severity
              </h2>
              <SeverityBars counts={m.severity_counts} />
              {Object.keys(m.family_counts).length > 0 && (
                <ul className="mt-4 flex flex-wrap gap-2 text-xs">
                  {Object.entries(m.family_counts).map(([fam, n]) => (
                    <li key={fam} className="rounded-md border border-line bg-surface-2 px-2 py-0.5">
                      {fam} <span className="font-semibold">{n}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
            <section className="card p-4" aria-labelledby="hist-h">
              <div className="mb-3 flex items-center justify-between">
                <h2 id="hist-h" className="font-semibold">
                  Recent scans
                </h2>
                <Link to="/scans" className="text-sm text-accent underline">
                  All scans
                </Link>
              </div>
              <ul className="divide-y divide-line">
                {m.latest_scans.map((s) => (
                  <li key={s.id}>
                    <Link to={`/scans/${s.id}`} className="flex items-center justify-between gap-3 py-2 hover:bg-surface-2 rounded px-1">
                      <span className="min-w-0">
                        <span className="block truncate text-sm font-medium">{s.repository_name}</span>
                        <span className="text-xs text-muted">
                          {MODE_LABEL[s.mode] ?? s.mode} · {timeAgo(s.created_at)}
                        </span>
                      </span>
                      <span className="flex items-center gap-3">
                        <span className="text-xs text-muted tabular-nums">
                          {s.blocking_findings}/{s.total_findings}
                        </span>
                        <ResultPill scan={s} />
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            </section>
          </div>

          <section className="card p-4" aria-labelledby="trend-h">
            <h2 id="trend-h" className="mb-2 font-semibold">
              Findings per scan
            </h2>
            <TrendChart points={m.trend} />
          </section>

          <section className="card" aria-labelledby="cur-h">
            <div className="flex items-center justify-between p-4 pb-2">
              <h2 id="cur-h" className="font-semibold">
                Current findings
              </h2>
              <Link to="/findings" className="text-sm text-accent underline">
                View all
              </Link>
            </div>
            {current.loading && !current.data && <Loading />}
            <ErrorState error={current.error} />
            {current.data && current.data.items.length === 0 && (
              <div className="p-4 pt-0">
                <EmptyState title="No current findings">Each repository's latest completed scan found nothing matching.</EmptyState>
              </div>
            )}
            {current.data && current.data.items.length > 0 && (
              <FindingTable findings={current.data.items} onSelect={(f) => navigate(`/findings/${f.id}`)} />
            )}
          </section>
        </div>
      )}
    </>
  );
}
