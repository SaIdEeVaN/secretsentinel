/**
 * Minimal API client for the loopback SecretSentinel backend.
 *
 * The backend only ever returns sanitized fields. The optional dashboard API
 * token (hosted/remote mode) is kept in memory and in sessionStorage, so it
 * survives a reload but is discarded when the tab closes. It is never written
 * to localStorage, and no third-party secret is ever stored.
 */

const BASE = (import.meta.env?.VITE_API_BASE ?? "/api/v1").replace(/\/$/, "");

const TOKEN_KEY = "secretsentinel.apiToken";
export const UNAUTHORIZED_EVENT = "secretsentinel:unauthorized";

function readStoredToken() {
  try {
    return window.sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

let authToken = readStoredToken();

export function setAuthToken(token) {
  authToken = token || null;
  try {
    if (authToken) window.sessionStorage.setItem(TOKEN_KEY, authToken);
    else window.sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: keep the token in memory only */
  }
}

export function hasAuthToken() {
  return Boolean(authToken);
}

export class ApiError extends Error {
  constructor(code, message, status, fields) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.fields = fields || [];
  }
}

function query(params = {}) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") qs.set(k, String(v));
  }
  const s = qs.toString();
  return s ? `?${s}` : "";
}

export async function request(path, { method = "GET", body, signal, responseType = "json" } = {}) {
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (authToken) headers.Authorization = `Bearer ${authToken}`;
  let res;
  try {
    res = await fetch(`${BASE}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal,
      credentials: "omit",
      cache: "no-store",
    });
  } catch (err) {
    if (err?.name === "AbortError") throw err;
    throw new ApiError("NETWORK_ERROR", "Cannot reach the SecretSentinel backend. Is `secretsentinel serve` running?", 0);
  }
  if (res.status === 204) return null;
  if (res.ok && responseType === "blob") return res.blob();
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) {
    const e = data?.error;
    if (res.status === 401) window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
    throw new ApiError(e?.code ?? `HTTP_${res.status}`, e?.message ?? "Request failed.", res.status, e?.fields);
  }
  return data;
}

export const api = {
  health: () => request("/health"),
  systemStatus: () => request("/system/status"),
  overview: () => request("/metrics/overview"),
  rules: () => request("/rules"),
  auditEvents: (params) => request(`/audit-events${query(params)}`),

  repositories: () => request("/repositories"),
  registerRepository: (path, displayName) =>
    request("/repositories", { method: "POST", body: { path, display_name: displayName || null } }),
  deleteRepository: (id) => request(`/repositories/${encodeURIComponent(id)}`, { method: "DELETE" }),
  createDemo: () => request("/demo", { method: "POST" }),

  scans: (params) => request(`/scans${query(params)}`),
  scan: (id) => request(`/scans/${encodeURIComponent(id)}`),
  startScan: (body) => request("/scans", { method: "POST", body }),
  cancelScan: (id) => request(`/scans/${encodeURIComponent(id)}/cancel`, { method: "POST" }),
  scanFindings: (id, params) => request(`/scans/${encodeURIComponent(id)}/findings${query(params)}`),
  exportScan: (id, format) => request(`/scans/${encodeURIComponent(id)}/export${query({ format })}`, { responseType: "blob" }),

  findings: (params) => request(`/findings${query(params)}`),
  finding: (id) => request(`/findings/${encodeURIComponent(id)}`),
  updateFinding: (id, status) => request(`/findings/${encodeURIComponent(id)}`, { method: "PATCH", body: { status } }),

  suppressions: (params) => request(`/suppressions${query(params)}`),
  createSuppression: (body) => request("/suppressions", { method: "POST", body }),
  deactivateSuppression: (id) => request(`/suppressions/${encodeURIComponent(id)}`, { method: "DELETE" }),

  attestation: (scanId) => request(`/attestations/${encodeURIComponent(scanId)}`),
  createAttestation: (scanId) => request(`/attestations/${encodeURIComponent(scanId)}`, { method: "POST" }),
  verifyAttestation: (body) => request("/attestations/verify", { method: "POST", body }),
};
