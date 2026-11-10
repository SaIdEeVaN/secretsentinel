export function formatDate(value) {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function timeAgo(value, now = Date.now()) {
  if (!value) return "—";
  const diff = Math.round((now - new Date(value).getTime()) / 1000);
  if (Number.isNaN(diff)) return "—";
  if (diff < 45) return "just now";
  const units = [
    [60, "minute"],
    [3600, "hour"],
    [86400, "day"],
    [2592000, "month"],
  ];
  let unit = ["second", 1];
  for (const [secs, name] of units) if (diff >= secs) unit = [name, secs];
  const n = Math.round(diff / unit[1]);
  return `${n} ${unit[0]}${n === 1 ? "" : "s"} ago`;
}

export function formatDuration(ms) {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  return s < 60 ? `${s.toFixed(1)} s` : `${Math.floor(s / 60)} m ${Math.round(s % 60)} s`;
}

export function shortSha(sha, n = 10) {
  return sha ? sha.slice(0, n) : "—";
}

export function location(f) {
  return f.start_line ? `${f.relative_path}:${f.start_line}` : f.relative_path || "—";
}

export const MODE_LABEL = { dir: "Directory", git: "Git history", both: "Dir + Git", ci: "CI" };
