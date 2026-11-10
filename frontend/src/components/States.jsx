export function Loading({ label = "Loading…" }) {
  return (
    <div role="status" aria-live="polite" className="flex items-center gap-3 p-6 text-muted">
      <span className="inline-block size-4 rounded-full border-2 border-accent border-t-transparent animate-spin" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

export function ErrorState({ error, onRetry }) {
  if (!error) return null;
  return (
    <div role="alert" className="card border-critical/60 p-4">
      <p className="font-semibold text-critical">
        <span aria-hidden="true">! </span>
        {error.message || "Something went wrong."}
      </p>
      {error.code && <p className="mt-1 text-xs text-muted mono">{error.code}</p>}
      {error.fields?.length > 0 && (
        <ul className="mt-2 list-disc pl-5 text-sm">
          {error.fields.map((f, i) => (
            <li key={i}>
              <span className="mono">{(f.loc || []).slice(1).join(".")}</span>: {f.msg}
            </li>
          ))}
        </ul>
      )}
      {onRetry && (
        <button type="button" className="btn btn-ghost mt-3" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyState({ title, children, action }) {
  return (
    <div className="card p-6 text-center">
      <p className="font-semibold">{title}</p>
      {children && <div className="mt-2 text-sm text-muted">{children}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
