import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client.js";
import FindingTable from "../components/FindingTable.jsx";
import { EmptyState, ErrorState, Loading } from "../components/States.jsx";
import { Field, PageHeader, Pagination } from "../components/Widgets.jsx";
import { MODE_LABEL } from "../components/format.js";
import { useAsync } from "../hooks/useAsync.js";
import { FindingDetailPanel } from "./FindingDetail.jsx";

const EMPTY = { severity: "", status: "", rule_id: "", mode: "", repository_id: "", blocking: "", latest_only: "true" };

export default function Findings() {
  const navigate = useNavigate();
  const [filters, setFilters] = useState(EMPTY);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState(null);
  const repos = useAsync(() => api.repositories(), []);
  const rules = useAsync(() => api.rules(), []);
  const list = useAsync(() => api.findings({ ...filters, page, page_size: 25 }), [filters, page]);
  const set = (k) => (e) => {
    setPage(1);
    setFilters((f) => ({ ...f, [k]: e.target.value }));
  };

  const select = (f) => {
    if (window.matchMedia && !window.matchMedia("(min-width: 1000px)").matches) navigate(`/findings/${f.id}`);
    else setSelected(f.id);
  };

  return (
    <>
      <PageHeader
        title="Findings"
        subtitle="Redacted findings only: rule, severity, location and status. Secret values are never available."
        actions={
          <button type="button" className="btn btn-ghost" onClick={() => { setPage(1); setFilters(EMPTY); }}>
            Reset filters
          </button>
        }
      />
      <form className="card mb-4 grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-4" aria-label="Filter findings" onSubmit={(e) => e.preventDefault()}>
        <Field label="Severity" htmlFor="ff-sev">
          <select id="ff-sev" className="input" value={filters.severity} onChange={set("severity")}>
            <option value="">Any</option>
            {["critical", "high", "medium", "low"].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </Field>
        <Field label="Status" htmlFor="ff-status">
          <select id="ff-status" className="input" value={filters.status} onChange={set("status")}>
            <option value="">Any</option>
            {["open", "acknowledged", "resolved", "suppressed"].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </Field>
        <Field label="Rule" htmlFor="ff-rule">
          <select id="ff-rule" className="input" value={filters.rule_id} onChange={set("rule_id")}>
            <option value="">Any</option>
            {(rules.data?.rules ?? []).map((r) => (
              <option key={r.rule_id} value={r.rule_id}>
                {r.rule_id}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Scan mode" htmlFor="ff-mode">
          <select id="ff-mode" className="input" value={filters.mode} onChange={set("mode")}>
            <option value="">Any</option>
            {Object.entries(MODE_LABEL).map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Repository" htmlFor="ff-repo">
          <select id="ff-repo" className="input" value={filters.repository_id} onChange={set("repository_id")}>
            <option value="">Any</option>
            {(repos.data ?? []).map((r) => (
              <option key={r.id} value={r.id}>
                {r.display_name}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Blocking" htmlFor="ff-block">
          <select id="ff-block" className="input" value={filters.blocking} onChange={set("blocking")}>
            <option value="">Any</option>
            <option value="true">Blocking only</option>
            <option value="false">Non-blocking only</option>
          </select>
        </Field>
        <Field label="Scope" htmlFor="ff-latest" hint="Latest = each repository's most recent completed scan.">
          <select id="ff-latest" className="input" value={filters.latest_only} onChange={set("latest_only")}>
            <option value="true">Latest scans</option>
            <option value="false">All history</option>
          </select>
        </Field>
      </form>

      <div className={`grid gap-5 ${selected ? "min-[1000px]:grid-cols-[minmax(0,1fr)_430px]" : ""}`}>
        <div className="min-w-0">
          {list.loading && !list.data && <Loading />}
          <ErrorState error={list.error} onRetry={list.reload} />
          {list.data && list.data.items.length === 0 && (
            <EmptyState title="No findings match these filters.">
              A clean result means no rule matched in the scanned scope; it is not a guarantee that no secrets exist.
            </EmptyState>
          )}
          {list.data && list.data.items.length > 0 && (
            <div className="card">
              <FindingTable findings={list.data.items} onSelect={select} selectedId={selected} compact={Boolean(selected)} />
              <Pagination page={page} pageSize={25} total={list.data.total} onPage={setPage} />
            </div>
          )}
        </div>
        {selected && (
          <aside
            className="hidden self-start min-[1000px]:sticky min-[1000px]:top-4 min-[1000px]:block min-[1000px]:max-h-[calc(100vh-2rem)] min-[1000px]:overflow-y-auto"
            aria-label="Finding details"
          >
            <FindingDetailPanel key={selected} findingId={selected} compact onChanged={list.reload} onClose={() => setSelected(null)} />
          </aside>
        )}
      </div>
    </>
  );
}
