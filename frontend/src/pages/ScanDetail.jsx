import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client.js";
import FindingTable from "../components/FindingTable.jsx";
import ScanStatus, { ResultPill } from "../components/ScanStatus.jsx";
import { EmptyState, ErrorState, Loading } from "../components/States.jsx";
import { KeyValue, PageHeader, Pagination } from "../components/Widgets.jsx";
import { MODE_LABEL, formatDate, formatDuration, shortSha } from "../components/format.js";
import { useAsync, usePolling } from "../hooks/useAsync.js";
import AttestationPanel from "./AttestationPanel.jsx";
import { localScanningEnabled, useSystem } from "../context/system.js";

export default function ScanDetail({ blockchainEnabled }) {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const { status: system } = useSystem();
  const [page, setPage] = useState(1);
  const [actionError, setActionError] = useState(null);
  const [actionBusy, setActionBusy] = useState(false);
  const [exportFormat, setExportFormat] = useState("json");
  const scan = useAsync(() => api.scan(scanId), [scanId]);
  const findings = useAsync(() => api.scanFindings(scanId, { page, page_size: 50 }), [scanId, page]);
  const s = scan.data;
  const active = s && (s.status === "queued" || s.status === "running");
  usePolling(
    () => {
      scan.reload();
      findings.reload();
    },
    1500,
    Boolean(active),
  );

  // The last findings request may finish before the scan's final transaction.
  // Refresh once the terminal status arrives so the final result is never stale.
  useEffect(() => {
    if (s && !active) findings.reload();
  }, [s?.status]);

  const cancel = async () => {
    setActionBusy(true);
    setActionError(null);
    try {
      await api.cancelScan(scanId);
      await scan.reload();
    } catch (error) {
      setActionError(error);
    } finally {
      setActionBusy(false);
    }
  };

  const exportReport = async () => {
    setActionBusy(true);
    setActionError(null);
    let url;
    try {
      const report = await api.exportScan(scanId, exportFormat);
      url = URL.createObjectURL(report);
      const link = document.createElement("a");
      link.href = url;
      link.download = `secretsentinel-${scanId}.${exportFormat}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      setActionError(error);
    } finally {
      if (url) setTimeout(() => URL.revokeObjectURL(url), 1000);
      setActionBusy(false);
    }
  };

  if (scan.loading && !s) return <Loading />;
  if (scan.error) return <ErrorState error={scan.error} onRetry={scan.reload} />;
  return (
    <>
      <PageHeader
        title={`Scan · ${s.repository_name}`}
        subtitle={`${MODE_LABEL[s.mode] ?? s.mode} scan started ${formatDate(s.created_at)}`}
        actions={
          <>
            <ResultPill scan={s} />
            {active && (
              <button type="button" className="btn btn-danger" onClick={cancel} disabled={actionBusy}>
                {actionBusy ? "Cancelling…" : "Cancel"}
              </button>
            )}
            {localScanningEnabled(system) && s.source !== "ingest" && (
              <Link to={`/scan/new?repository=${s.repository_id}`} className="btn btn-ghost">
                Rescan
              </Link>
            )}
          </>
        }
      />
      <div className="space-y-5">
        <ErrorState error={actionError} />
        <ScanStatus scan={s} />
        {s.status === "completed" && (
          <section className="card flex flex-wrap items-end gap-3 p-4" aria-label="Export report">
            <div className="min-w-40">
              <label className="label" htmlFor="export-format">Report format</label>
              <select className="input" id="export-format" value={exportFormat} onChange={(event) => setExportFormat(event.target.value)}>
                <option value="json">JSON</option>
                <option value="csv">CSV</option>
                <option value="sarif">SARIF</option>
              </select>
            </div>
            <button type="button" className="btn btn-ghost" disabled={actionBusy} onClick={exportReport}>
              {actionBusy ? "Preparing report…" : "Download report"}
            </button>
            <p className="text-xs text-muted">All findings from this scan, with secret values redacted.</p>
          </section>
        )}
        {s.warnings.length > 0 && (
          <div className="card border-warn/50 p-4 text-sm">
            <p className="font-semibold text-warn">Warnings</p>
            <ul className="mt-1 list-disc pl-5">
              {s.warnings.map((w, i) => (
                <li key={i}>{w}</li>
              ))}
            </ul>
          </div>
        )}
        <section className="card p-4" aria-labelledby="meta-h">
          <h2 id="meta-h" className="mb-3 font-semibold">
            Scan details
          </h2>
          <KeyValue
            items={[
              ["Scope", <span className="mono">{s.scope || "—"}</span>],
              ["Commit", <span className="mono">{shortSha(s.commit_sha, 12)}</span>],
              ["Blocks at", s.fail_on || "—"],
              ["Duration", formatDuration(s.duration_ms)],
              ["Scanner", <span className="mono">gitleaks {s.scanner_version ?? "—"}</span>],
              ["SecretSentinel", <span className="mono">{s.secretsentinel_version ?? "—"}</span>],
              ["Ruleset", <span className="mono">{s.ruleset_version ?? "—"}</span>],
              ["Ruleset digest", <span className="mono">{s.ruleset_digest ?? "—"}</span>],
              ["Policy digest", <span className="mono">{s.policy_digest ?? "—"}</span>],
              ["Source", s.source],
            ]}
          />
        </section>

        <section className="card" aria-labelledby="f-h">
          <h2 id="f-h" className="p-4 pb-2 font-semibold">
            Findings ({s.total_findings})
          </h2>
          {findings.loading && !findings.data && <Loading />}
          <ErrorState error={findings.error} />
          {findings.data && findings.data.items.length === 0 && (
            <div className="p-4 pt-0">
              <EmptyState title={s.status === "completed" ? "No findings in this scan." : "No findings recorded."}>
                {s.status !== "completed" && "A scan that did not complete records no findings; its security status is unknown."}
              </EmptyState>
            </div>
          )}
          {findings.data && findings.data.items.length > 0 && (
            <>
              <FindingTable findings={findings.data.items} showRepo={false} onSelect={(f) => navigate(`/findings/${f.id}`)} />
              <Pagination page={page} pageSize={50} total={findings.data.total} onPage={setPage} />
            </>
          )}
        </section>

        {blockchainEnabled && s.status === "completed" && <AttestationPanel scanId={s.id} />}
      </div>
    </>
  );
}
