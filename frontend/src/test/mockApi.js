import { vi } from "vitest";

/** Install a fetch mock. ``routes`` maps "METHOD /path" (prefix match) to a body or (init, url) => body. */
export function mockApi(routes) {
  const calls = [];
  const fetchMock = vi.fn(async (url, init = {}) => {
    const method = (init.method || "GET").toUpperCase();
    const path = String(url).replace(/^\/api\/v1/, "");
    calls.push({ method, path, init });
    const key = Object.keys(routes)
      .filter((k) => {
        const [m, p] = k.split(" ");
        return m === method && path.split("?")[0] === p.split("?")[0];
      })
      .sort((a, b) => b.length - a.length)[0];
    if (!key) {
      return new Response(JSON.stringify({ error: { code: "NOT_FOUND", message: "not mocked" } }), { status: 404 });
    }
    const value = typeof routes[key] === "function" ? routes[key](init, path) : routes[key];
    if (value && value.__status) {
      return new Response(JSON.stringify(value.body), { status: value.__status });
    }
    return new Response(JSON.stringify(value), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, fetchMock };
}

export const STATUS = {
  version: "1.0.0",
  app_env: "development",
  scanner: { available: true, version: "8.30.1", error_code: null, message: null },
  git_available: true,
  ruleset_version: "1.0.0",
  ruleset_digest: "sha256:abc",
  allowed_roots: ["/home/dev/repos"],
  default_fail_on: "high",
  timeout_seconds: 120,
  max_file_mb: 10,
  max_concurrent_scans: 1,
  auth_required: false,
  blockchain_enabled: false,
  local_scanning_enabled: true,
  ingest_enabled: false,
  hosted: false,
};

export function finding(overrides = {}) {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    scan_id: "22222222-2222-4222-8222-222222222222",
    scan_mode: "both",
    repository_id: "33333333-3333-4333-8333-333333333333",
    repository_name: "demo",
    fingerprint: "ss1:0123456789abcdef0123456789abcdef",
    rule_id: "web3-evm-private-key-assignment",
    rule_family: "web3-signing-key",
    title: "Potential EVM signing secret",
    severity: "critical",
    confidence: "high",
    requirement: "W3-01",
    relative_path: "src/config.js",
    start_line: 21,
    end_line: 21,
    commit_sha: "a".repeat(40),
    sources: ["dir", "git"],
    also_matched: [],
    status: "open",
    suppression_id: null,
    blocking: true,
    remediation_key: "ROTATE_SIGNING_KEY",
    first_seen_at: "2026-11-10T10:00:00Z",
    last_seen_at: "2026-11-10T10:00:00Z",
    status_updated_at: null,
    ...overrides,
  };
}

export function scan(overrides = {}) {
  return {
    id: "22222222-2222-4222-8222-222222222222",
    repository_id: "33333333-3333-4333-8333-333333333333",
    repository_name: "demo",
    source: "api",
    mode: "both",
    status: "completed",
    policy_result: "fail",
    fail_on: "high",
    since_ref: null,
    scope: "working-tree+full-history",
    commit_sha: "b".repeat(40),
    scanner_name: "gitleaks",
    scanner_version: "8.30.1",
    secretsentinel_version: "1.0.0",
    ruleset_version: "1.0.0",
    ruleset_digest: "sha256:abc",
    policy_digest: "sha256:def",
    created_at: "2026-11-10T10:00:00Z",
    started_at: "2026-11-10T10:00:00Z",
    finished_at: "2026-11-10T10:00:01Z",
    duration_ms: 1000,
    total_findings: 2,
    blocking_findings: 1,
    suppressed_findings: 0,
    severity_counts: { critical: 1, high: 0, medium: 1, low: 0 },
    error_code: null,
    error_message: null,
    warnings: [],
    ...overrides,
  };
}
