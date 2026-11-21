import { useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { useAsync } from "./useAsync.js";

const MAX_PAGE = 100_000; // API pagination limit

export const REPOSITORY_ID = /^[a-zA-Z0-9_-]{1,36}$/;

function readFilters(search, defaults, allowed) {
  return Object.fromEntries(Object.entries(defaults).map(([key, fallback]) => {
    const value = search.get(key) ?? "";
    const valid = Array.isArray(allowed[key]) ? allowed[key].includes(value) : allowed[key].test(value);
    return [key, valid ? value : fallback];
  }));
}

export function useListSearch({ defaults, allowed, pageSize, load }) {
  const [search, setSearch] = useSearchParams();
  const filters = readFilters(search, defaults, allowed);
  const filterKey = new URLSearchParams(filters).toString();
  const rawPage = Number(search.get("page"));
  const page = Number.isInteger(rawPage) && rawPage >= 1 && rawPage <= MAX_PAGE ? rawPage : 1;
  const viewKey = `${filterKey}&page=${page}`;
  const list = useAsync(() => load({ ...filters, page, page_size: pageSize }), [], viewKey);

  const lastPage = list.data ? Math.max(1, Math.ceil(list.data.total / pageSize)) : null;
  useEffect(() => {
    if (lastPage === null || page <= lastPage) return;
    const next = new URLSearchParams(search);
    if (lastPage === 1) next.delete("page");
    else next.set("page", String(lastPage));
    setSearch(next, { replace: true });
  }, [lastPage, page, search, setSearch]);

  function choose(key, value) {
    if (filters[key] === value) return;
    const next = new URLSearchParams(search);
    if (value === defaults[key]) next.delete(key);
    else next.set(key, value);
    next.delete("page");
    setSearch(next);
  }

  function setPage(value) {
    if (value === page || value < 1 || value > MAX_PAGE) return;
    const next = new URLSearchParams(search);
    if (value === 1) next.delete("page");
    else next.set("page", String(value));
    setSearch(next);
  }

  function reset() {
    const next = new URLSearchParams(search);
    for (const key of Object.keys(defaults)) next.delete(key);
    next.delete("page");
    if (next.toString() !== search.toString()) setSearch(next);
  }

  return { filters, filterKey, viewKey, page, list, choose, setPage, reset };
}
