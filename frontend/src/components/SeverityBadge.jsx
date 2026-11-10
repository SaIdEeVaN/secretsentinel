const SEVERITY = {
  critical: { label: "Critical", icon: "◆", cls: "text-critical bg-critical-bg border-critical/40" },
  high: { label: "High", icon: "▲", cls: "text-high bg-high-bg border-high/40" },
  medium: { label: "Medium", icon: "●", cls: "text-medium bg-medium-bg border-medium/40" },
  low: { label: "Low", icon: "○", cls: "text-low bg-low-bg border-low/40" },
};

/** Severity pill: icon + text so meaning never depends on colour alone. */
export default function SeverityBadge({ severity, compact = false }) {
  const s = SEVERITY[severity] ?? { label: severity ?? "Unknown", icon: "?", cls: "text-muted border-line" };
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-xs font-semibold whitespace-nowrap ${s.cls}`}
      title={`Severity: ${s.label} (detector risk estimate)`}
    >
      <span aria-hidden="true">{s.icon}</span>
      {compact ? <span className="sr-only">{s.label}</span> : s.label}
    </span>
  );
}

export function ConfidenceLabel({ confidence }) {
  const label = { high: "High", medium: "Medium", low: "Low" }[confidence] ?? confidence;
  return (
    <span className="text-xs text-muted whitespace-nowrap" title="Confidence that this is a real secret (estimate)">
      {label} conf.
    </span>
  );
}

export const SEVERITY_ORDER = ["critical", "high", "medium", "low"];
export const SEVERITY_META = SEVERITY;
