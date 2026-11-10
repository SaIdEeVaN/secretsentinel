import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client.js";
import { ResultPill } from "../components/ScanStatus.jsx";
import { EmptyState, ErrorState, Loading } from "../components/States.jsx";
import { Field, PageHeader, Pagination } from "../components/Widgets.jsx";
import { MODE_LABEL, formatDate, formatDuration } from "../components/format.js";
import { useAsync, usePolling } from "../hooks/useAsync.js";

export default function Scans() {
  const navigate = useNavigate();
  const [filters, setFilters] = useState({ status: "", mode: "", policy_result: "" });
  const [page, setPage] = useState(1);
  const list = useAsync(() => api.scans({ ...filters, page, page_size: 20 }), [filters, page]);
  usePolling(list.reload, 1500, Boolean(list.data?.items.some((s) => s.status === "queued" || s.status === "running")));
  const set = (k) => (e) => {
    setPage(1);
    setFilters((f) => ({ ...f, [k]: e.target.value }));
  };
  const open = (s) => navigate(`/scans/${s.id}`);

  return (
    <>
      <PageHeader title="Scan History" subtitle="Every run, with mode, result and the scanner/ruleset versions used." />
      <div className="card mb-4 grid gap-3 p-4 sm:grid-cols-3">
        <Field label="Status" htmlFor="f-status">
          <select id="f-status" className="input" value={filters.status} onChange={set("status")}>
            <option value="">Any</option>
            {["queued", "running", "completed", "failed", "cancelled"].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </Field>
        <Field label="Mode" htmlFor="f-mode">
          <select id="f-mode" className="input" value={filters.mode} onChange={set("mode")}>
            <option value="">Any</option>
            {Object.entries(MODE_LABEL).map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Policy result" htmlFor="f-result">
          <select id="f-result" className="input" value={filters.policy_result} onChange={set("policy_result")}>
            <option value="">Any</option>
            <option value="pass">pass</option>
            <option value="fail">fail</option>
            <option value="not_evaluated">not evaluated (error)</option>
          </select>
        </Field>
      </div>
      {list.loading && !list.data && <Loading />}
      <ErrorState error={list.error} onRetry={list.reload} />
      {list.data && list.data.items.length === 0 && <EmptyState title="No scans match these filters." />}
      {list.data && list.data.items.length > 0 && (
        <div className="card">
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Started</th>
                  <th scope="col">Repository</th>
                  <th scope="col">Mode</th>
                  <th scope="col">Result</th>
                  <th scope="col">Blocking / total</th>
                  <th scope="col" className="hidden md:table-cell">
                    Scanner
                  </th>
                  <th scope="col" className="hidden md:table-cell">
                    Duration
                  </th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((s) => (
                  <tr
                    key={s.id}
                    className="row-link"
                    tabIndex={0}
                    onClick={() => open(s)}
                    onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), open(s))}
                  >
                    <td className="whitespace-nowrap text-sm">{formatDate(s.created_at)}</td>
                    <td className="text-sm">
                      {s.repository_name}
                      <div className="text-xs text-muted">{s.source}</div>
                    </td>
                    <td className="text-sm whitespace-nowrap">{MODE_LABEL[s.mode] ?? s.mode}</td>
                    <td>
                      <ResultPill scan={s} />
                      {s.error_code && <div className="mt-1 text-xs mono text-warn">{s.error_code}</div>}
                    </td>
                    <td className="tabular-nums text-sm">
                      {s.blocking_findings} / {s.total_findings}
                    </td>
                    <td className="hidden md:table-cell text-xs text-muted mono">
                      gitleaks {s.scanner_version ?? "—"}
                      <br />
                      rules {s.ruleset_version ?? "—"}
                    </td>
                    <td className="hidden md:table-cell text-xs text-muted">{formatDuration(s.duration_ms)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination page={page} pageSize={20} total={list.data.total} onPage={setPage} />
        </div>
      )}
    </>
  );
}
