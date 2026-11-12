import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client.js";
import { ResultPill } from "../components/ScanStatus.jsx";
import { EmptyState, ErrorState, Loading } from "../components/States.jsx";
import { ChipGroup, Field, PageHeader, Pagination } from "../components/Widgets.jsx";
import { MODE_LABEL, formatDate, formatDuration, shortSha, timeAgo } from "../components/format.js";
import { useAsync, usePolling } from "../hooks/useAsync.js";

const RESULT_CHIPS = [
  ["pass", "Pass"],
  ["fail", "Fail"],
  ["not_evaluated", "Error / cancelled"],
];
const EMPTY = { status: "", mode: "", policy_result: "", repository_id: "" };

export default function Scans() {
  const navigate = useNavigate();
  const [filters, setFilters] = useState(EMPTY);
  const [page, setPage] = useState(1);
  const list = useAsync(() => api.scans({ ...filters, page, page_size: 20 }), [filters, page]);
  const repos = useAsync(() => api.repositories(), []);
  usePolling(list.reload, 1500, Boolean(list.data?.items.some((s) => s.status === "queued" || s.status === "running")));
  const choose = (k, v) => {
    setPage(1);
    setFilters((f) => ({ ...f, [k]: v }));
  };
  const set = (k) => (e) => choose(k, e.target.value);
  const open = (s) => navigate(`/scans/${s.id}`);

  return (
    <>
      <PageHeader title="Scan History" subtitle="Every run, including failed and cancelled ones, with the scanner and ruleset used." />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <ChipGroup label="Result" options={RESULT_CHIPS} value={filters.policy_result} onChange={(v) => choose("policy_result", v)} />
      </div>
      <form className="card mb-4 grid gap-3 p-4 min-[640px]:grid-cols-3" aria-label="More filters" onSubmit={(e) => e.preventDefault()}>
        <Field label="Repository" htmlFor="f-repo">
          <select id="f-repo" className="input" value={filters.repository_id} onChange={set("repository_id")}>
            <option value="">All</option>
            {(Array.isArray(repos.data) ? repos.data : []).map((r) => (
              <option key={r.id} value={r.id}>
                {r.display_name}
              </option>
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
        <Field label="Status" htmlFor="f-status">
          <select id="f-status" className="input" value={filters.status} onChange={set("status")}>
            <option value="">Any</option>
            {["queued", "running", "completed", "failed", "cancelled"].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </Field>
      </form>
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
                  <th scope="col" className="hidden md:table-cell">
                    Commit
                  </th>
                  <th scope="col" className="hidden md:table-cell">
                    Time
                  </th>
                  <th scope="col" className="hidden min-[1000px]:table-cell">
                    Scanner
                  </th>
                  <th scope="col">Blk / all</th>
                  <th scope="col" className="text-right">
                    Result
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
                    <td className="whitespace-nowrap text-sm">
                      <time dateTime={s.created_at} title={formatDate(s.created_at)}>
                        {timeAgo(s.created_at)}
                      </time>
                    </td>
                    <td className="text-sm">
                      {s.repository_name}
                      <div className="text-xs text-muted">{s.source}</div>
                    </td>
                    <td className="mono whitespace-nowrap text-xs">{MODE_LABEL[s.mode] ?? s.mode}</td>
                    <td className="mono hidden text-xs md:table-cell">{shortSha(s.commit_sha, 7)}</td>
                    <td className="hidden whitespace-nowrap text-xs text-muted md:table-cell">{formatDuration(s.duration_ms)}</td>
                    <td className="mono hidden text-xs text-muted min-[1000px]:table-cell">
                      gitleaks {s.scanner_version ?? "—"}
                      <br />
                      rules {s.ruleset_version ?? "—"}
                    </td>
                    <td className="mono tabular-nums text-sm">
                      {s.blocking_findings}/{s.total_findings}
                    </td>
                    <td className="text-right">
                      <ResultPill scan={s} />
                      {s.error_code && <div className="mono mt-1 text-xs text-warn">{s.error_code}</div>}
                    </td>
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
