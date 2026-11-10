import { useCallback, useEffect, useRef, useState } from "react";

/** Run an async loader and expose { data, error, loading, reload }. */
export function useAsync(loader, deps = []) {
  const [state, setState] = useState({ data: null, error: null, loading: true });
  const loaderRef = useRef(loader);
  loaderRef.current = loader;
  const seq = useRef(0);

  const run = useCallback(async () => {
    const id = ++seq.current;
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const data = await loaderRef.current();
      if (id === seq.current) setState({ data, error: null, loading: false });
    } catch (error) {
      if (id === seq.current) setState((s) => ({ data: s.data, error, loading: false }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    run();
  }, [run]);

  return { ...state, reload: run };
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
