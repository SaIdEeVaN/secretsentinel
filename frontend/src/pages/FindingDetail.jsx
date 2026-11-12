import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client.js";
import SeverityBadge from "../components/SeverityBadge.jsx";
import { StatusTag } from "../components/FindingTable.jsx";
import { ErrorState, Loading } from "../components/States.jsx";
import { Field, KeyValue } from "../components/Widgets.jsx";
import { formatDate, location, shortSha, timeAgo } from "../components/format.js";
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

const STATUS_OPTIONS = [
  ["open", "Open"],
  ["acknowledged", "Acknowledged"],
  ["resolved", "Resolved"],
];

function describeEvent(e) {
  const m = e.metadata || {};
  if (e.action === "finding.status_changed") return `Status changed: ${m.previous ?? "?"} → ${m.new ?? "?"}`;
  if (e.action === "suppression.created") return "Suppression recorded";
  if (e.action === "suppression.deactivated") return "Suppression removed";
  return e.action.replace(/[._]/g, " ");
}

/** Why a finding is suppressed: reviewed dashboard entry, or a policy-file entry. */
export function SuppressionDetails({ finding }) {
  const s = finding.suppression;
  const today = new Date().toISOString().slice(0, 10);
  const expired = s?.expires_at && s.expires_at < today;
  return (
    <div className="mt-1 space-y-2">
      {s?.origin === "dashboard" ? (
        <dl className="grid grid-cols-[72px_minmax(0,1fr)] gap-x-2.5 gap-y-1 rounded-md border border-line p-2.5 text-xs" aria-label="Suppression">
          <dt className="text-faint">Reason</dt>
          <dd className="break-words">{s.reason}</dd>
          <dt className="text-faint">Expires</dt>
          <dd className={expired ? "text-warn" : undefined}>
            {s.expires_at}
            {expired ? " (expired: it no longer applies to new scans)" : ""}
          </dd>
          <dt className="text-faint">Reviewer</dt>
          <dd className="break-words">{s.reviewer}</dd>
        </dl>
      ) : (
        <p className="text-xs text-muted">
          Suppressed by the policy file entry <span className="mono">{finding.suppression_id}</span> (a reviewed entry in the
          repository's <span className="mono">.secretsentinel.yml</span>).
        </p>
      )}
      {s?.origin === "dashboard" && s.active === false && (
        <p className="text-xs text-warn">This suppression was deactivated; the next scan reports the finding again.</p>
      )}
      <p className="text-xs text-muted">
        Manage suppressions on{" "}
        <Link className="text-accent underline" to="/rules">
          Rules & Policy
        </Link>
        .
      </p>
    </div>
  );
}

/** A section: a plain captioned block in the side panel, a card on the full page. */
function Block({ id, title, compact, children }) {
  if (compact) {
    return (
      <section aria-labelledby={id} className="space-y-1.5">
        <h3 id={id} className="text-[11px] font-normal uppercase tracking-wider text-faint">
          {title}
        </h3>
        {children}
      </section>
    );
  }
  return (
    <section className="card p-4" aria-labelledby={id}>
      <h3 id={id} className="font-semibold">
        {title}
      </h3>
      {children}
    </section>
  );
}

export function FindingDetailPanel({ findingId, onChanged, onClose, compact = false }) {
  const detail = useAsync(() => api.finding(findingId), [findingId]);
  // The audit trail is part of the side panel only; the full page stays as it was.
  const audit = useAsync(() => (compact ? api.auditEvents({ entity_id: findingId, limit: 10 }) : Promise.resolve([])), [findingId, compact]);
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
      audit.reload();
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
  const events = Array.isArray(audit.data) ? audit.data : [];
  return (
    <article className={compact ? "card" : "space-y-5"} aria-labelledby="fd-title">
      {compact && (
        <div className="flex items-center justify-between border-b border-line py-2 pl-4 pr-2">
          <span className="mono text-[11px] text-faint">finding {shortSha(f.id, 8)}</span>
          {onClose && (
            <button type="button" className="btn btn-ghost text-xs" onClick={onClose}>
              Close
            </button>
          )}
        </div>
      )}
      <div className={compact ? "space-y-4 p-4" : "space-y-5"}>
        <header>
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={f.severity} />
            {compact ? (
              <span className="text-xs text-muted">
                Confidence {f.confidence} <span className="text-faint">· both are estimates</span>
              </span>
            ) : (
              <StatusTag finding={f} />
            )}
            {!f.still_detected && <span className="text-xs text-ok">✓ Not detected in the latest scan</span>}
          </div>
          <h2 id="fd-title" className={`mt-2 font-bold ${compact ? "text-lg" : "text-xl"}`}>
            {f.title}
          </h2>
          <p className="mono text-xs text-muted">
            {f.rule_id}
            {compact && f.rule_family ? ` · ${f.rule_family}` : ""}
          </p>
          {compact && (
            <p className="mt-1">
              <StatusTag finding={f} />
            </p>
          )}
        </header>

        {compact ? (
          <div className="grid grid-cols-[14px_1fr] gap-2.5 rounded-md border border-line bg-sidebar p-2.5 text-xs text-muted">
            <span aria-hidden="true" className="mt-1 size-2.5 rounded-sm border-[1.5px] border-muted" />
            <span>
              Matched value not retained. SecretSentinel keeps the rule, location and a random finding ID. There is no way to reveal the
              value here.
            </span>
          </div>
        ) : null}

        <section className={compact ? "" : "card p-4"} aria-label="Finding details">
          <KeyValue
            rows={compact}
            items={[
              ["Repository", f.repository_name],
              ["Location", <span className="mono">{location(f)}</span>],
              ["Commit", <span className="mono">{shortSha(f.commit_sha, 12)}</span>],
              ["Detected by", f.sources.join(" + ") || f.scan_mode],
              ...(compact ? [] : [["Severity (estimate)", f.severity], ["Confidence (estimate)", f.confidence]]),
              ["First seen", formatDate(f.first_seen_at)],
              ["Last seen", formatDate(f.last_seen_at)],
              ["Seen in scans", f.occurrences],
              ["Requirement", f.requirement ?? "—"],
              ["Also matched", f.also_matched.length ? <span className="mono">{f.also_matched.join(", ")}</span> : "—"],
              ["Scan", <Link className="text-accent underline" to={`/scans/${f.scan_id}`}>{shortSha(f.scan_id, 8)}</Link>],
            ]}
          />
          {!compact && (
            <p className="mt-4 rounded-md border border-line bg-surface-2 p-2 text-xs text-muted">
              <span aria-hidden="true">🔒 </span>The detected value is redacted by the scanner and never stored, returned or displayed.
              There is no way to reveal it here - open the file locally if you need to inspect it.
            </p>
          )}
        </section>

        <Block id="triage-h" title="Triage status" compact={compact}>
          {f.status === "suppressed" ? (
            <SuppressionDetails finding={f} />
          ) : (
            <>
              {compact ? (
                <div className="flex overflow-hidden rounded-md border border-line" role="group" aria-label="Set status">
                  {STATUS_OPTIONS.map(([v, l]) => (
                    <button
                      key={v}
                      type="button"
                      aria-pressed={f.status === v}
                      disabled={busy}
                      onClick={() => setStatus(v)}
                      className={`min-h-9 flex-1 border-r border-line px-2 py-1.5 text-xs last:border-r-0 ${
                        f.status === v ? "bg-surface-2 font-semibold text-ink" : "text-muted hover:text-ink"
                      }`}
                    >
                      {l}
                    </button>
                  ))}
                </div>
              ) : (
                <>
                  <p className="mt-1 text-xs text-muted">
                    Status changes are audited. Acknowledging does not unblock the gate; mark resolved only after the credential was
                    rotated and removed.
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
                </>
              )}
              {compact && (
                <p className="text-[11px] text-faint">
                  {f.status === "resolved"
                    ? "Mark resolved only after completing the response yourself. Changes are timestamped."
                    : "Changes are timestamped in the audit trail."}
                </p>
              )}
              <ErrorState error={error} />
              {compact && (
                <div className="flex flex-wrap items-center gap-2.5 pt-1">
                  <button type="button" className="btn btn-ghost text-xs" aria-expanded={showSuppress} onClick={() => setShowSuppress((v) => !v)}>
                    Suppress…
                  </button>
                  <span className="text-[11px] text-faint">Requires a justification and an expiry date.</span>
                </div>
              )}
              {showSuppress && (
                <div className="mt-4">
                  <SuppressForm
                    finding={f}
                    onDone={() => {
                      setShowSuppress(false);
                      detail.reload();
                      audit.reload();
                      onChanged && onChanged();
                    }}
                  />
                </div>
              )}
            </>
          )}
        </Block>

        <Block id="risk-h" title="Why this matters" compact={compact}>
          <p className={compact ? "text-[12.5px]" : "mt-1 text-sm"}>{rem.risk}</p>
          {f.rule_description && <p className="mt-2 text-xs text-muted">Rule: {f.rule_description}</p>}
        </Block>

        <Block id="rem-h" title={compact ? "Recommended response" : `Recommended response: ${rem.title}`} compact={compact}>
          {compact && <p className="text-[12.5px] font-semibold">{rem.title}</p>}
          <ol className={compact ? "list-decimal space-y-1.5 pl-5 text-[12.5px]" : "mt-2 list-decimal space-y-1.5 pl-5 text-sm"}>
            {rem.steps.map((st, i) => (
              <li key={i}>{st}</li>
            ))}
          </ol>
          {rem.notes.length > 0 && (
            <ul className={`space-y-1 text-xs ${compact ? "" : "mt-3"}`}>
              {rem.notes.map((n, i) => (
                <li key={i} className={/does not revoke/i.test(n) ? "text-warn" : "text-muted"}>
                  ⓘ {n}
                </li>
              ))}
            </ul>
          )}
        </Block>

        {compact && (
          <Block id="audit-h" title="Audit trail" compact>
            {events.length === 0 ? (
              <p className="text-xs text-muted">No recorded changes yet.</p>
            ) : (
              <ul className="space-y-1.5">
                {events.map((e) => (
                  <li key={e.id} className="grid grid-cols-[92px_1fr] gap-2 text-xs">
                    <time className="mono text-[11px] text-faint" dateTime={e.occurred_at} title={formatDate(e.occurred_at)}>
                      {timeAgo(e.occurred_at)}
                    </time>
                    <span>{describeEvent(e)}</span>
                  </li>
                ))}
              </ul>
            )}
          </Block>
        )}
      </div>
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
