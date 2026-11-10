import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client.js";
import SeverityBadge from "../components/SeverityBadge.jsx";
import { StatusTag } from "../components/FindingTable.jsx";
import { ErrorState, Loading } from "../components/States.jsx";
import { Field, KeyValue } from "../components/Widgets.jsx";
import { formatDate, location, shortSha } from "../components/format.js";
import { useAsync } from "../hooks/useAsync.js";

function addDays(days) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString().slice(0, 10);
}

function SuppressForm({ finding, onDone }) {
  const [reason, setReason] = useState("");
  const [reviewer, setReviewer] = useState("");
  const [expires, setExpires] = useState(addDays(90));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.createSuppression({ finding_id: finding.id, reason: reason.trim(), reviewer: reviewer.trim(), expires_at: expires });
      onDone();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="space-y-3" aria-label="Record a reviewed suppression">
      <p className="text-xs text-muted">
        Only suppress after review (e.g. confirmed false positive or synthetic value). Suppressions need a reason, a reviewer and an
        expiry date of at most one year; expired suppressions stop applying automatically. Never suppress a real credential instead of
        rotating it.
      </p>
      <Field label="Justification (min. 10 characters)" htmlFor="sup-reason">
        <textarea id="sup-reason" className="input" rows={3} value={reason} onChange={(e) => setReason(e.target.value)} minLength={10} maxLength={500} required />
      </Field>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Reviewer" htmlFor="sup-reviewer">
          <input id="sup-reviewer" className="input" value={reviewer} onChange={(e) => setReviewer(e.target.value)} maxLength={120} required />
        </Field>
        <Field label="Re-review / expiry date" htmlFor="sup-expires">
          <input id="sup-expires" type="date" className="input" value={expires} min={addDays(0)} max={addDays(366)} onChange={(e) => setExpires(e.target.value)} required />
        </Field>
      </div>
      <button type="submit" className="btn btn-ghost" disabled={busy || reason.trim().length < 10 || !reviewer.trim()}>
        {busy ? "Saving…" : "Record suppression"}
      </button>
      <ErrorState error={error} />
    </form>
  );
}

export function FindingDetailPanel({ findingId, onChanged, compact = false }) {
  const detail = useAsync(() => api.finding(findingId), [findingId]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [showSuppress, setShowSuppress] = useState(false);
  const f = detail.data;

  const setStatus = async (status) => {
    setBusy(true);
    setError(null);
    try {
      await api.updateFinding(findingId, status);
      await detail.reload();
      onChanged && onChanged();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  if (detail.loading && !f) return <Loading />;
  if (detail.error) return <ErrorState error={detail.error} onRetry={detail.reload} />;
  const rem = f.remediation;
  return (
    <article className="space-y-5" aria-labelledby="fd-title">
      <header>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={f.severity} />
          <StatusTag finding={f} />
          {!f.still_detected && <span className="text-xs text-ok">✓ Not detected in the latest scan</span>}
        </div>
        <h2 id="fd-title" className={`mt-2 font-bold ${compact ? "text-lg" : "text-xl"}`}>
          {f.title}
        </h2>
        <p className="mono text-xs text-muted">{f.rule_id}</p>
      </header>

      <section className="card p-4">
        <KeyValue
          items={[
            ["Repository", f.repository_name],
            ["Location", <span className="mono">{location(f)}</span>],
            ["Commit", <span className="mono">{shortSha(f.commit_sha, 12)}</span>],
            ["Detected by", f.sources.join(" + ") || f.scan_mode],
            ["Severity (estimate)", f.severity],
            ["Confidence (estimate)", f.confidence],
            ["First seen", formatDate(f.first_seen_at)],
            ["Last seen", formatDate(f.last_seen_at)],
            ["Seen in scans", f.occurrences],
            ["Requirement", f.requirement ?? "—"],
            ["Also matched", f.also_matched.length ? <span className="mono">{f.also_matched.join(", ")}</span> : "—"],
            ["Scan", <Link className="text-accent underline" to={`/scans/${f.scan_id}`}>{shortSha(f.scan_id, 8)}</Link>],
          ]}
        />
        <p className="mt-4 rounded-md border border-line bg-surface-2 p-2 text-xs text-muted">
          <span aria-hidden="true">🔒 </span>The detected value is redacted by the scanner and never stored, returned or displayed. There is no
          way to reveal it here - open the file locally if you need to inspect it.
        </p>
      </section>

      <section className="card p-4" aria-labelledby="risk-h">
        <h3 id="risk-h" className="font-semibold">
          Why this matters
        </h3>
        <p className="mt-1 text-sm">{rem.risk}</p>
        {f.rule_description && <p className="mt-2 text-xs text-muted">Rule: {f.rule_description}</p>}
      </section>

      <section className="card p-4" aria-labelledby="rem-h">
        <h3 id="rem-h" className="font-semibold">
          Recommended response: {rem.title}
        </h3>
        <ol className="mt-2 list-decimal space-y-1.5 pl-5 text-sm">
          {rem.steps.map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ol>
        {rem.notes.length > 0 && (
          <ul className="mt-3 space-y-1 text-xs text-muted">
            {rem.notes.map((n, i) => (
              <li key={i}>ⓘ {n}</li>
            ))}
          </ul>
        )}
      </section>

      <section className="card p-4" aria-labelledby="triage-h">
        <h3 id="triage-h" className="font-semibold">
          Triage
        </h3>
        {f.status === "suppressed" ? (
          <p className="mt-1 text-sm text-muted">
            Suppressed by <span className="mono">{f.suppression_id}</span>. Manage suppressions on{" "}
            <Link className="text-accent underline" to="/rules">
              Rules & Policy
            </Link>
            .
          </p>
        ) : (
          <>
            <p className="mt-1 text-xs text-muted">
              Status changes are audited. Acknowledging does not unblock the gate; mark resolved only after the credential was rotated and
              removed.
            </p>
            <div className="mt-3 flex flex-wrap gap-2" role="group" aria-label="Set status">
              {[
                ["open", "Open"],
                ["acknowledged", "Acknowledge"],
                ["resolved", "Mark resolved"],
              ].map(([v, l]) => (
                <button key={v} type="button" className={`btn ${f.status === v ? "btn-primary" : "btn-ghost"}`} aria-pressed={f.status === v} disabled={busy} onClick={() => setStatus(v)}>
                  {l}
                </button>
              ))}
              <button type="button" className="btn btn-ghost" aria-expanded={showSuppress} onClick={() => setShowSuppress((v) => !v)}>
                Suppress…
              </button>
            </div>
            <ErrorState error={error} />
            {showSuppress && (
              <div className="mt-4">
                <SuppressForm
                  finding={f}
                  onDone={() => {
                    setShowSuppress(false);
                    detail.reload();
                    onChanged && onChanged();
                  }}
                />
              </div>
            )}
          </>
        )}
      </section>
    </article>
  );
}

export default function FindingDetail() {
  const { findingId } = useParams();
  return (
    <>
      <p className="mb-3 text-sm">
        <Link to="/findings" className="text-accent underline">
          ← All findings
        </Link>
      </p>
      <FindingDetailPanel findingId={findingId} />
    </>
  );
}
