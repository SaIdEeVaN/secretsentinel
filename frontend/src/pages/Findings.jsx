import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client.js";
import FindingTable from "../components/FindingTable.jsx";
import { EmptyState, ErrorState, Loading } from "../components/States.jsx";
import { Field, PageHeader, Pagination } from "../components/Widgets.jsx";
import { MODE_LABEL } from "../components/format.js";
import { useAsync } from "../hooks/useAsync.js";
import { FindingDetailPanel } from "./FindingDetail.jsx";

const SEVERITY_CHIPS = [["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]];
const STATUS_CHIPS = [["open", "Open"], ["acknowledged", "Acknowledged"], ["resolved", "Resolved"], ["suppressed", "Suppressed"]];

function sum(counts) {
  return counts ? Object.values(counts).reduce((a, b) => a + b, 0) : null;
}

/** A joined row of toggle buttons with optional counts (design: segmented filter). */
function ChipGroup({ label, options, value, counts, onChange }) {
  const all = [["", "All", sum(counts)], ...options.map(([v, l]) => [v, l, counts ? counts[v] ?? 0 : null])];
  return (
    <div role="group" aria-label={label} className="flex flex-wrap overflow-hidden rounded-md border border-line">
      {all.map(([v, l, n]) => (
        <button
          key={v || "all"}
          type="button"
          aria-pressed={value === v}
          onClick={() => onChange(v)}
          className={`min-h-8 border-r border-line px-2.5 py-1.5 text-xs last:border-r-0 ${
            value === v ? "bg-surface-2 font-semibold text-ink" : "text-muted hover:text-ink"
          }`}
        >
          {l}
          {n != null && <span className="mono ml-1.5 text-faint">{n}</span>}
        </button>
      ))}
    </div>
  );
}

const EMPTY = { severity: "", status: "", rule_id: "", mode: "", repository_id: "", blocking: "", latest_only: "true" };

export default function Findings() {
  const navigate = useNavigate();
  const [filters, setFilters] = useState(EMPTY);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState(null);
  const repos = useAsync(() => api.repositories(), []);
  const rules = useAsync(() => api.rules(), []);
  const list = useAsync(() => api.findings({ ...filters, page, page_size: 25 }), [filters, page]);
  // Counts for the chips; if they fail to load the chips simply show no numbers.
  const facets = useAsync(() => api.findingFacets(filters), [filters]);
  const counts = facets.error ? null : facets.data;
  const choose = (k, v) => {
    setPage(1);
    setFilters((f) => ({ ...f, [k]: v }));
  };
  const set = (k) => (e) => choose(k, e.target.value);
  const refresh = () => {
    list.reload();
    facets.reload();
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
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <ChipGroup label="Severity" options={SEVERITY_CHIPS} value={filters.severity} counts={counts?.severity} onChange={(v) => choose("severity", v)} />
        <ChipGroup label="Status" options={STATUS_CHIPS} value={filters.status} counts={counts?.status} onChange={(v) => choose("status", v)} />
      </div>
      {counts && (
        <p className="mb-3 flex items-center gap-2.5 rounded-lg border border-line bg-surface px-3 py-2 text-[12.5px] text-muted">
          <span className={`mono ${counts.status.open ? "text-warn" : "text-ok"}`}>{counts.status.open}</span>
          <span>
            open finding{counts.status.open === 1 ? "" : "s"} {filters.latest_only === "true" ? "in the latest scans" : "across all scan history"}.
            Resolved and suppressed findings are kept for review.
          </span>
        </p>
      )}
      <form className="card mb-4 grid gap-3 p-4 min-[640px]:grid-cols-2 min-[1000px]:grid-cols-5" aria-label="More filters" onSubmit={(e) => e.preventDefault()}>
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
            <FindingDetailPanel key={selected} findingId={selected} compact onChanged={refresh} onClose={() => setSelected(null)} />
          </aside>
        )}
      </div>
    </>
  );
}
