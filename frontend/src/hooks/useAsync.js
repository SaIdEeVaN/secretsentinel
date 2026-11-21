import { useCallback, useEffect, useRef, useState } from "react";

const pending = { data: null, error: null, loading: true };

/** Run a loader, optionally keeping results only within the same scope. */
export function useAsync(loader, deps = [], scope) {
  const [state, setState] = useState(pending);
  const requestRef = useRef({ loader, scope });
  requestRef.current = { loader, scope };
  const seq = useRef(0);

  const run = useCallback(async () => {
    const { loader: load, scope: requestScope } = requestRef.current;
    const id = ++seq.current;
    setState((s) => ({ ...(s.scope === requestScope ? s : pending), loading: true, error: null, scope: requestScope }));
    try {
      const data = await load();
      if (id === seq.current) setState({ data, error: null, loading: false, scope: requestScope });
    } catch (error) {
      if (id === seq.current) setState((s) => ({ ...s, error, loading: false }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope, ...deps]);

  useEffect(() => {
    run();
  }, [run]);

  const { data, error, loading } = state.scope === scope ? state : pending;
  return { data, error, loading, reload: run };
}

/** Poll ``fn`` every ``ms`` while ``active`` is true. */
export function usePolling(fn, ms, active) {
  const fnRef = useRef(fn);
  fnRef.current = fn;
  useEffect(() => {
    if (!active) return undefined;
    const t = setInterval(() => fnRef.current(), ms);
    return () => clearInterval(t);
  }, [ms, active]);
}
