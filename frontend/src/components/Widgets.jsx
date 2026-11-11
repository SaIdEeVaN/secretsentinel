import { SEVERITY_META, SEVERITY_ORDER } from "./SeverityBadge.jsx";

export function PageHeader({ title, subtitle, actions }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-xl font-bold tracking-tight sm:text-2xl">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

export function StatCard({ label, value, hint, tone }) {
  const toneCls = { danger: "text-critical", ok: "text-ok", warn: "text-warn" }[tone] ?? "text-ink";
  return (
    <div className="card p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-muted">{label}</p>
      <p className={`mt-1 text-2xl font-bold tabular-nums ${toneCls}`}>{value ?? "—"}</p>
      {hint && <p className="mt-1 text-xs text-muted">{hint}</p>}
    </div>
  );
}

export function SeverityBars({ counts }) {
  const max = Math.max(1, ...SEVERITY_ORDER.map((s) => counts?.[s] ?? 0));
  const bar = { critical: "bg-critical", high: "bg-high", medium: "bg-medium", low: "bg-low" };
  const ink = { critical: "text-critical", high: "text-high", medium: "text-medium", low: "text-low" };
  return (
    <ul className="space-y-2.5" aria-label="Open findings by severity">
      {SEVERITY_ORDER.map((s) => {
        const n = counts?.[s] ?? 0;
        return (
          <li key={s} className="grid grid-cols-[6.5rem_1fr_2.5rem] items-center gap-3 text-sm">
            <span className="flex items-center gap-1.5">
              <span aria-hidden="true" className={ink[s]}>
                {SEVERITY_META[s].icon}
              </span>
              {SEVERITY_META[s].label}
            </span>
            <span className="h-2.5 rounded-full bg-surface-2 overflow-hidden" aria-hidden="true">
              <span className={`block h-full rounded-full ${bar[s]}`} style={{ width: `${(n / max) * 100}%` }} />
            </span>
            <span className="text-right tabular-nums font-semibold">{n}</span>
          </li>
        );
      })}
    </ul>
  );
}

/** Small accessible SVG bar chart: total vs blocking findings per scan. */
export function TrendChart({ points }) {
  if (!points?.length) return <p className="text-sm text-muted">Trends appear after a few scans.</p>;
  const w = 600;
  const h = 140;
  const pad = 24;
  const max = Math.max(1, ...points.map((p) => p.total_findings));
  const bw = Math.min(28, Math.max(4, (w - pad * 2) / points.length - 4));
  return (
    <figure>
      <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-36" role="img" aria-label="Findings per scan, oldest to newest">
        <line x1={pad} y1={h - pad} x2={w - pad} y2={h - pad} stroke="var(--border)" />
        {points.map((p, i) => {
          const x = pad + i * ((w - pad * 2) / points.length) + 2;
          const th = ((h - pad * 2) * p.total_findings) / max;
          const bh = ((h - pad * 2) * p.blocking_findings) / max;
          return (
            <g key={p.scan_id}>
              <title>{`${p.repository_name}: ${p.total_findings} total, ${p.blocking_findings} blocking (${p.status})`}</title>
              <rect x={x} y={h - pad - th} width={bw} height={th} rx="2" fill="var(--surface-2)" stroke="var(--border)" />
              <rect x={x} y={h - pad - bh} width={bw} height={bh} rx="2" fill="var(--critical)" />
              {p.status === "failed" && (
                <text x={x + bw / 2} y={h - pad - 4} textAnchor="middle" fontSize="11" fill="var(--warn)">
                  !
                </text>
              )}
            </g>
          );
        })}
        <text x={pad} y={14} fontSize="11" fill="var(--muted)">
          max {max}
        </text>
      </svg>
      <figcaption className="mt-1 flex gap-4 text-xs text-muted">
        <span>
          <span className="inline-block size-2.5 rounded-sm bg-critical align-middle" aria-hidden="true" /> blocking
        </span>
        <span>
          <span className="inline-block size-2.5 rounded-sm border border-line bg-surface-2 align-middle" aria-hidden="true" /> total
        </span>
        <span>! = failed scan</span>
      </figcaption>
    </figure>
  );
}

export function Pagination({ page, pageSize, total, onPage }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (total <= pageSize) return null;
  return (
    <nav aria-label="Pagination" className="flex items-center justify-between gap-3 p-3 text-sm">
      <span className="text-muted">
        Page {page} of {pages} · {total} items
      </span>
      <span className="flex gap-2">
        <button type="button" className="btn btn-ghost" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          ← Prev
        </button>
        <button type="button" className="btn btn-ghost" disabled={page >= pages} onClick={() => onPage(page + 1)}>
          Next →
        </button>
      </span>
    </nav>
  );
}

export function Field({ label, htmlFor, hint, children }) {
  return (
    <div>
      <label className="label" htmlFor={htmlFor}>
        {label}
      </label>
      {children}
      {hint && <p className="mt-1 text-xs text-muted">{hint}</p>}
    </div>
  );
}

export function KeyValue({ items, rows = false }) {
  if (rows) {
    return (
      <dl className="grid grid-cols-[96px_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-[12.5px]">
        {items.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-faint">{k}</dt>
            <dd className="min-w-0 break-words">{v ?? "—"}</dd>
          </div>
        ))}
      </dl>
    );
  }
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">
      {items.map(([k, v]) => (
        <div key={k} className="min-w-0">
          <dt className="text-xs font-semibold uppercase tracking-wide text-muted">{k}</dt>
          <dd className="mt-0.5 text-sm break-words">{v ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}
