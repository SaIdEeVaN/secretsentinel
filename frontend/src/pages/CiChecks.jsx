import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api/client.js";
import { FAILED_TEXT, ResultPill, resultOf } from "../components/ScanStatus.jsx";
import { EmptyState, ErrorState, Loading } from "../components/States.jsx";
import { PageHeader } from "../components/Widgets.jsx";
import { formatDate, formatDuration, location, shortSha, timeAgo } from "../components/format.js";
import { useAsync } from "../hooks/useAsync.js";

// Most recent CI uploads to group by repository. 200 is the API maximum and
// covers several weeks of weekly fleet scans plus pushes.
const RECENT = 200;
const RUNS_SHOWN = 5;
const LOG_FINDINGS = 25;

const MARK = {
  pass: { mark: "✓", cls: "text-ok" },
  fail: { mark: "✕", cls: "text-critical" },
  error: { mark: "!", cls: "text-warn" },
  cancelled: { mark: "–", cls: "text-muted" },
  queued: { mark: "…", cls: "text-muted" },
  running: { mark: "●", cls: "text-accent" },
  unknown: { mark: "?", cls: "text-muted" },
};

const RUN_WORD = { pass: "passed", fail: "failed", error: "error", cancelled: "cancelled", queued: "queued", running: "running", unknown: "unknown" };

/** Group CI scans (newest first) by repository, keeping each repository's recent runs. */
export function groupByRepository(scans) {
  const groups = new Map();
  for (const s of scans) {
    if (!groups.has(s.repository_id)) groups.set(s.repository_id, { id: s.repository_id, name: s.repository_name, runs: [] });
    groups.get(s.repository_id).runs.push(s);
  }
  return [...groups.values()];
}

function headline(scan) {
  const r = resultOf(scan);
  if (r === "pass") return { text: `No blocking findings at or above “${scan.fail_on}”.`, sub: "The scan completed and the policy passed." };
  if (r === "fail") {
    return {
      text: `${scan.blocking_findings} blocking finding(s) at or above “${scan.fail_on}”.`,
      sub: "Review them on the Findings page. Rotate real credentials before removing them from history.",
    };
  }
  if (r === "cancelled") return { text: "Scan cancelled; security status is unknown.", sub: "Run the workflow again." };
  return { text: FAILED_TEXT, sub: scan.error_code ? `${scan.error_code}${scan.error_message ? ` — ${scan.error_message}` : ""}` : "Check the workflow run in GitHub Actions." };
}

const STRIP = { pass: "border-ok/50 bg-ok-bg", fail: "border-critical/60 bg-critical-bg", error: "border-warn/60 bg-warn-bg" };

/** A sanitized log built only from stored metadata: no matched text, no source lines. */
function RunLog({ scan }) {
  const r = resultOf(scan);
  const findings = useAsync(
    () => (r === "pass" || r === "fail" ? api.findings({ scan_id: scan.id, latest_only: false, page_size: LOG_FINDINGS }) : Promise.resolve(null)),
    [scan.id],
  );
  const lines = [
    ["m", `secretsentinel ${scan.secretsentinel_version ?? "?"} · gitleaks ${scan.scanner_version ?? "?"} · ruleset ${scan.ruleset_digest ? `${scan.ruleset_digest.slice(0, 14)}…` : "?"}`],
    ["m", `commit ${shortSha(scan.commit_sha, 12)} · ${scan.scope ?? "working tree + full history"}`],
    ["i", `▸ finished ${formatDate(scan.finished_at ?? scan.created_at)} · ${formatDuration(scan.duration_ms)}`],
  ];
  if (r === "pass" || r === "fail") {
    for (const f of findings.data?.items ?? []) {
      const mark = f.blocking ? "✕" : "·";
      lines.push([f.blocking ? "f" : "i", `${mark} ${f.severity.toUpperCase().padEnd(9)} ${f.rule_id}  ${location(f)}  ${shortSha(f.commit_sha, 8)}`]);
    }
    if ((findings.data?.total ?? 0) > LOG_FINDINGS) lines.push(["m", `  … ${findings.data.total - LOG_FINDINGS} more on the Findings page`]);
    lines.push(["m", `  matched values redacted · ${scan.blocking_findings} blocking · ${scan.total_findings} total · ${scan.suppressed_findings} suppressed`]);
    lines.push([r === "pass" ? "p" : "f", `${r === "pass" ? "✓" : "✕"} policy fail-on=${scan.fail_on} → ${r === "pass" ? "PASS" : "FAIL"}`]);
  } else {
    lines.push(["w", `! ${scan.error_code ?? "scan did not complete"}`]);
  }
  const color = { m: "text-faint", i: "text-ink", f: "text-critical", p: "text-ok", w: "text-warn" };
  return (
    <section className="overflow-hidden rounded-lg border border-line bg-sidebar" aria-label="Sanitized scan log">
      <div className="flex items-center justify-between border-b border-line px-3.5 py-2 text-xs">
        <span className="font-semibold">Sanitized log</span>
        <span className="mono text-[11px] text-faint">built from stored metadata only</span>
      </div>
      <div className="overflow-x-auto px-3.5 py-2.5">
        {findings.loading && !findings.data && r !== "error" ? <Loading label="Loading findings…" /> : null}
        <ErrorState error={findings.error} onRetry={findings.reload} />
        {lines.map(([k, t], i) => (
          <div key={i} className={`mono whitespace-pre text-xs leading-relaxed ${color[k]}`}>
            {t}
          </div>
        ))}
      </div>
    </section>
  );
}

function RepoDetail({ group }) {
  const [runId, setRunId] = useState(group.runs[0].id);
  const scan = group.runs.find((s) => s.id === runId) ?? group.runs[0];
  const r = resultOf(scan);
  const h = headline(scan);
  return (
    <div className="min-w-0 space-y-3">
      <section className="card space-y-3 p-4" aria-labelledby="ci-repo">
        <div>
          <p className="mono text-[11px] text-faint">GitHub Actions · sanitized upload</p>
          <h2 id="ci-repo" className="text-lg font-semibold tracking-tight">
            {group.name}
          </h2>
        </div>
        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Recent runs">
          {group.runs.slice(0, RUNS_SHOWN).map((s, i) => {
            const active = s.id === scan.id;
            return (
              <button
                key={s.id}
                type="button"
                aria-pressed={active}
                onClick={() => setRunId(s.id)}
                className={`rounded-md border px-2.5 py-1 text-xs ${active ? "border-muted bg-surface-2 text-ink" : "border-line text-muted hover:text-ink"}`}
              >
                {i === 0 ? "Latest" : timeAgo(s.created_at)} · {RUN_WORD[resultOf(s)]}
              </button>
            );
          })}
        </div>
        <div className={`flex flex-wrap items-center gap-3 rounded-lg border p-3 ${STRIP[r] ?? "border-line bg-surface-2"}`} role="status">
          <ResultPill scan={scan} />
          <div className="min-w-[200px] flex-1">
            <p className="font-medium">{h.text}</p>
            <p className="text-xs text-muted">{h.sub}</p>
          </div>
          <Link to={`/scans/${scan.id}`} className="btn btn-ghost text-xs">
            Scan details
          </Link>
        </div>
        <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-line bg-line text-xs min-[1000px]:grid-cols-4">
          {[
            ["Commit", shortSha(scan.commit_sha, 10)],
            ["Uploaded", timeAgo(scan.created_at)],
            ["Duration", formatDuration(scan.duration_ms)],
            ["Findings", `${scan.blocking_findings} blocking / ${scan.total_findings}`],
          ].map(([k, v]) => (
            <div key={k} className="bg-surface px-2.5 py-2">
              <dt className="text-[11px] text-faint">{k}</dt>
              <dd className="mono">{v}</dd>
            </div>
          ))}
        </dl>
      </section>
      <RunLog key={scan.id} scan={scan} />
    </div>
  );
}

export default function CiChecks() {
  const [params, setParams] = useSearchParams();
  const list = useAsync(() => api.scans({ mode: "ci", page: 1, page_size: RECENT }), []);
  const groups = useMemo(() => groupByRepository(list.data?.items ?? []), [list.data]);
  const selectedId = params.get("repository") ?? groups[0]?.id;
  const selected = groups.find((g) => g.id === selectedId) ?? groups[0];

  return (
    <>
      <PageHeader
        title="CI Checks"
        subtitle="Scans run by GitHub Actions and uploaded as sanitized reports: one row per repository, newest run first."
      />
      {list.loading && !list.data && <Loading />}
      <ErrorState error={list.error} onRetry={list.reload} />
      {list.data && groups.length === 0 && (
        <EmptyState title="No CI uploads yet.">
          Scans appear here after a GitHub Actions workflow uploads a report (see docs/HOSTING.md). The pull-request gate itself never
          uploads anything.
        </EmptyState>
      )}
      {selected && (
        <div className="grid items-start gap-4 lg:grid-cols-[300px_minmax(0,1fr)]">
          <section className="card overflow-hidden" aria-labelledby="ci-list-h">
            <h2 id="ci-list-h" className="border-b border-line px-3.5 py-2.5 text-xs font-semibold">
              Repositories · {groups.length}
            </h2>
            <ul>
              {groups.map((g) => {
                const latest = g.runs[0];
                const m = MARK[resultOf(latest)];
                const active = g.id === selected.id;
                return (
                  <li key={g.id}>
                    <button
                      type="button"
                      aria-current={active ? "true" : undefined}
                      onClick={() => setParams({ repository: g.id })}
                      className={`grid w-full grid-cols-[18px_minmax(0,1fr)] gap-2.5 border-b border-line px-3.5 py-2.5 text-left last:border-b-0 ${
                        active ? "bg-surface-2" : "hover:bg-surface-2"
                      }`}
                    >
                      <span className={`mono ${m.cls}`} aria-hidden="true">
                        {m.mark}
                      </span>
                      <span className="min-w-0">
                        <span className="block truncate text-sm">{g.name}</span>
                        <span className="mono block truncate text-[11px] text-faint">
                          {shortSha(latest.commit_sha, 7)} · {timeAgo(latest.created_at)} · {RUN_WORD[resultOf(latest)]}
                        </span>
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </section>
          <RepoDetail key={selected.id} group={selected} />
        </div>
      )}
    </>
  );
}
