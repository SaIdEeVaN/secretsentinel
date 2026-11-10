import SeverityBadge, { ConfidenceLabel } from "./SeverityBadge.jsx";
import { location, shortSha, timeAgo } from "./format.js";

const STATUS_LABEL = {
  open: "Open",
  acknowledged: "Acknowledged",
  resolved: "Resolved",
  suppressed: "Suppressed",
};

export function StatusTag({ finding }) {
  if (finding.blocking) {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-bold text-critical whitespace-nowrap">
        <span aria-hidden="true">⛔</span> Blocking · {STATUS_LABEL[finding.status] ?? finding.status}
      </span>
    );
  }
  return <span className="text-xs text-muted whitespace-nowrap">{STATUS_LABEL[finding.status] ?? finding.status}</span>;
}

/**
 * Renders ONLY sanitized metadata. There is deliberately no column, tooltip
 * or button that could show a secret value - the API never returns one.
 */
export default function FindingTable({ findings, onSelect, selectedId, showRepo = true, compact = false }) {
  const repoCol = showRepo && !compact;
  const activate = (f) => onSelect && onSelect(f);
  const onKey = (e, f) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      activate(f);
    }
  };
  return (
    <>
      {/* Table on medium+ screens */}
      <div className="hidden md:block overflow-x-auto">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Severity</th>
              <th scope="col">Finding</th>
              <th scope="col">Location</th>
              {repoCol && <th scope="col">Repository</th>}
              <th scope="col">Status</th>
              {!compact && <th scope="col">Last seen</th>}
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr
                key={f.id}
                className={`row-link ${selectedId === f.id ? "bg-surface-2" : ""}`}
                tabIndex={0}
                aria-current={selectedId === f.id ? "true" : undefined}
                onClick={() => activate(f)}
                onKeyDown={(e) => onKey(e, f)}
              >
                <td>
                  <SeverityBadge severity={f.severity} />
                </td>
                <td>
                  <div className="font-medium">{f.title}</div>
                  <div className="text-xs text-muted mono">{f.rule_id}</div>
                </td>
                <td>
                  <div className="mono">{location(f)}</div>
                  {f.commit_sha && <div className="text-xs text-muted mono whitespace-nowrap">commit {shortSha(f.commit_sha, 8)}</div>}
                </td>
                {repoCol && <td className="text-sm">{f.repository_name}</td>}
                <td>
                  <StatusTag finding={f} />
                  <div>
                    <ConfidenceLabel confidence={f.confidence} />
                  </div>
                </td>
                {!compact && <td className="text-xs text-muted whitespace-nowrap">{timeAgo(f.last_seen_at)}</td>}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {/* Stacked cards on phones */}
      <ul className="md:hidden divide-y divide-line">
        {findings.map((f) => (
          <li key={f.id}>
            <button
              type="button"
              className={`w-full text-left p-3 ${selectedId === f.id ? "bg-surface-2" : ""}`}
              onClick={() => activate(f)}
            >
              <div className="flex items-center justify-between gap-2">
                <SeverityBadge severity={f.severity} />
                <StatusTag finding={f} />
              </div>
              <div className="mt-1 font-medium">{f.title}</div>
              <div className="mt-0.5 text-xs mono text-muted">{location(f)}</div>
            </button>
          </li>
        ))}
      </ul>
    </>
  );
}
