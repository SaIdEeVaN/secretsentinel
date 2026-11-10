/**
 * Scan result presentation. Wording follows the PRD exactly:
 * - clean:  "No matching secrets detected in the scanned scope." (never "100% secure")
 * - failed: "Scan could not complete; security status is unknown."
 */

export const CLEAN_TEXT = "No matching secrets detected in the scanned scope.";
export const FAILED_TEXT = "Scan could not complete; security status is unknown.";

export function resultOf(scan) {
  if (!scan) return "unknown";
  if (scan.status === "queued" || scan.status === "running") return scan.status;
  if (scan.status === "cancelled") return "cancelled";
  if (scan.status !== "completed") return "error";
  return scan.policy_result === "fail" ? "fail" : "pass";
}

const PILL = {
  pass: { label: "PASS", icon: "✓", cls: "text-ok bg-ok-bg border-ok/40" },
  fail: { label: "FAIL", icon: "✕", cls: "text-critical bg-critical-bg border-critical/40" },
  error: { label: "ERROR", icon: "!", cls: "text-warn bg-warn-bg border-warn/40" },
  cancelled: { label: "CANCELLED", icon: "–", cls: "text-muted bg-surface-2 border-line" },
  queued: { label: "QUEUED", icon: "…", cls: "text-muted bg-surface-2 border-line" },
  running: { label: "RUNNING", icon: "⟳", cls: "text-accent bg-surface-2 border-accent/40" },
  unknown: { label: "UNKNOWN", icon: "?", cls: "text-muted bg-surface-2 border-line" },
};

export function ResultPill({ scan }) {
  const r = resultOf(scan);
  const p = PILL[r];
  return (
    <span className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-xs font-bold tracking-wide ${p.cls}`}>
      <span aria-hidden="true">{p.icon}</span>
      {p.label}
    </span>
  );
}

export default function ScanStatus({ scan }) {
  const r = resultOf(scan);
  if (r === "queued" || r === "running") {
    return (
      <div role="status" aria-live="polite" className="card p-4 flex items-center gap-3">
        <span className="inline-block size-3 rounded-full bg-accent animate-pulse" aria-hidden="true" />
        <div>
          <p className="font-semibold">{r === "queued" ? "Scan queued…" : "Scan running…"}</p>
          <p className="text-sm text-muted">Results appear when the scan completes. Raw scanner output is never shown.</p>
        </div>
      </div>
    );
  }
  if (r === "error" || r === "cancelled") {
    return (
      <div role="status" aria-live="polite" className="card p-4 border-warn/60 bg-warn-bg">
        <p className="font-semibold text-warn">
          <span aria-hidden="true">! </span>
          {r === "cancelled" ? "Scan cancelled; security status is unknown." : FAILED_TEXT}
        </p>
        {scan?.error_code && (
          <p className="mt-1 text-sm">
            <span className="mono">{scan.error_code}</span> — {scan.error_message}
          </p>
        )}
      </div>
    );
  }
  if (r === "pass" && scan.total_findings === 0) {
    return (
      <div role="status" aria-live="polite" className="card p-4 border-ok/50 bg-ok-bg">
        <p className="font-semibold text-ok">
          <span aria-hidden="true">✓ </span>
          {CLEAN_TEXT}
        </p>
        <p className="mt-1 text-sm text-muted">This is not a guarantee that no secrets exist outside the scanned scope or rules.</p>
      </div>
    );
  }
  const fail = r === "fail";
  return (
    <div role="status" aria-live="polite" className={`card p-4 ${fail ? "border-critical/60 bg-critical-bg" : "border-ok/50 bg-ok-bg"}`}>
      <p className={`font-semibold ${fail ? "text-critical" : "text-ok"}`}>
        <span aria-hidden="true">{fail ? "✕ " : "✓ "}</span>
        {fail
          ? `${scan.blocking_findings} blocking finding(s) at or above “${scan.fail_on}”.`
          : `No blocking findings at or above “${scan.fail_on}”.`}
      </p>
      <p className="mt-1 text-sm">
        {scan.total_findings} total · {scan.suppressed_findings} suppressed. Secret values are redacted and never stored.
      </p>
    </div>
  );
}
