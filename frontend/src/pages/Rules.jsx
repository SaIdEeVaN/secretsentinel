import { useState } from "react";
import { api } from "../api/client.js";
import SeverityBadge from "../components/SeverityBadge.jsx";
import { EmptyState, ErrorState, Loading } from "../components/States.jsx";
import { PageHeader } from "../components/Widgets.jsx";
import { formatDate } from "../components/format.js";
import { useAsync } from "../hooks/useAsync.js";

const POLICY_EXAMPLE = `# .secretsentinel.yml (review changes like code; protect with CODEOWNERS)
version: 1
fail_on: high            # critical | high | medium | low | none
exclude_paths:           # not scanned at all - keep this list short
  - "build/**"
suppressions:            # reviewed exceptions; expire automatically
  - id: SUP-001
    rule_id: web3-evm-private-key-assignment
    path: "docs/tutorial/*.md"
    reason: "Publicly documented local-devnet key used in the tutorial"
    reviewer: "security-team"
    expires: 2027-03-31
baseline: .secretsentinel-baseline.json   # optional, see 'secretsentinel baseline create'`;

export default function Rules() {
  const rules = useAsync(() => api.rules(), []);
  const sups = useAsync(() => api.suppressions(), []);
  const [web3Only, setWeb3Only] = useState(false);
  const [error, setError] = useState(null);

  const deactivate = async (id) => {
    setError(null);
    try {
      await api.deactivateSuppression(id);
      sups.reload();
    } catch (e) {
      setError(e);
    }
  };

  const list = (rules.data?.rules ?? []).filter((r) => !web3Only || r.web3);
  return (
    <>
      <PageHeader
        title="Rules & Policy"
        subtitle="Gitleaks default rules extended with a small, context-driven Web3 rule set. Severity and confidence are estimates."
      />
      {rules.loading && !rules.data && <Loading />}
      <ErrorState error={rules.error} onRetry={rules.reload} />
      {rules.data && (
        <div className="space-y-5">
          <section className="card p-4 text-sm">
            <p>
              Ruleset <span className="mono">{rules.data.ruleset_version}</span> · digest{" "}
              <span className="mono">{rules.data.ruleset_digest}</span>
            </p>
            <p className="mt-2 text-muted">
              Rules not listed below are Gitleaks defaults and use severity <strong>{rules.data.default_severity}</strong>. Findings in
              example/test paths get <em>lower confidence</em> but keep their severity - a real key under <span className="mono">tests/</span>{" "}
              is still a real key.
            </p>
            <details className="mt-2">
              <summary className="cursor-pointer text-accent">Paths that lower confidence</summary>
              <ul className="mt-2 flex flex-wrap gap-2">
                {rules.data.low_confidence_paths.map((p) => (
                  <li key={p} className="mono rounded border border-line bg-surface-2 px-1.5">
                    {p}
                  </li>
                ))}
              </ul>
            </details>
          </section>

          <section className="card" aria-labelledby="rules-h">
            <div className="flex flex-wrap items-center justify-between gap-2 p-4 pb-2">
              <h2 id="rules-h" className="font-semibold">
                Mapped rules ({list.length})
              </h2>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={web3Only} onChange={(e) => setWeb3Only(e.target.checked)} /> Web3 rules only
              </label>
            </div>
            <div className="overflow-x-auto">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Severity</th>
                    <th scope="col">Rule</th>
                    <th scope="col">Family</th>
                    <th scope="col" className="hidden md:table-cell">
                      Confidence
                    </th>
                    <th scope="col" className="hidden md:table-cell">
                      Req.
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {list.map((r) => (
                    <tr key={r.rule_id}>
                      <td>
                        <SeverityBadge severity={r.severity} />
                      </td>
                      <td>
                        <div className="font-medium">{r.title}</div>
                        <div className="mono text-xs text-muted">{r.rule_id}</div>
                        {r.description && <div className="mt-0.5 text-xs text-muted">{r.description}</div>}
                      </td>
                      <td className="text-xs">{r.family}</td>
                      <td className="hidden md:table-cell text-xs">{r.confidence}</td>
                      <td className="hidden md:table-cell text-xs mono">{r.requirement ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="card p-4" aria-labelledby="sup-h">
            <h2 id="sup-h" className="font-semibold">
              Dashboard suppressions
            </h2>
            <p className="mt-1 text-xs text-muted">
              Recorded from finding details; applied to future scans of the same repository until they expire or are deactivated.
            </p>
            <ErrorState error={error || sups.error} />
            {sups.data && sups.data.length === 0 && (
              <div className="mt-3">
                <EmptyState title="No suppressions recorded." />
              </div>
            )}
            {sups.data && sups.data.length > 0 && (
              <div className="mt-3 overflow-x-auto">
                <table className="table">
                  <thead>
                    <tr>
                      <th scope="col">Rule / location</th>
                      <th scope="col">Reason</th>
                      <th scope="col">Reviewer</th>
                      <th scope="col">Expires</th>
                      <th scope="col">
                        <span className="sr-only">Actions</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {sups.data.map((s) => (
                      <tr key={s.id}>
                        <td>
                          <div className="mono text-xs">{s.rule_id}</div>
                          <div className="mono text-xs text-muted">
                            {s.path}
                            {s.line ? `:${s.line}` : ""}
                          </div>
                        </td>
                        <td className="text-sm">{s.reason}</td>
                        <td className="text-sm">{s.reviewer}</td>
                        <td className="text-sm whitespace-nowrap">
                          {s.expires_at}
                          {!s.active && <div className="text-xs text-muted">inactive</div>}
                          {s.active && s.expired && <div className="text-xs text-warn">expired</div>}
                          <div className="text-xs text-muted">added {formatDate(s.created_at)}</div>
                        </td>
                        <td>
                          {s.active && (
                            <button type="button" className="btn btn-ghost text-xs" onClick={() => deactivate(s.id)}>
                              Deactivate
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="card p-4" aria-labelledby="pol-h">
            <h2 id="pol-h" className="font-semibold">
              Repository policy file
            </h2>
            <p className="mt-1 text-sm text-muted">
              Policy lives in the scanned repository so it is versioned and reviewed. Suppressions without a reason, reviewer or valid
              expiry are ignored and the finding keeps blocking. In CI, the policy is read from the protected base branch.
            </p>
            <pre className="mono mt-3 overflow-x-auto rounded-lg border border-line bg-surface-2 p-3 text-xs leading-relaxed">{POLICY_EXAMPLE}</pre>
          </section>
        </div>
      )}
    </>
  );
}
