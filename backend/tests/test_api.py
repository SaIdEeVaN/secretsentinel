"""FastAPI contract, validation, security middleware and triage workflow."""

import time
from datetime import date, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from secretsentinel.core.config import Settings
from secretsentinel.main import create_app, validate_startup
from secretsentinel.core.errors import SecretSentinelError

from .conftest import raw_record

HEX64 = "0123456789abcdef" * 4


@pytest.fixture
def root(tmp_path) -> Path:
    r = tmp_path / "allowed"
    (r / "proj").mkdir(parents=True)
    return r.resolve()


@pytest.fixture
def make_client(tmp_path, root, fake_gitleaks):
    def make(**overrides):
        settings = Settings(
            gitleaks_path=fake_gitleaks.path,
            db_url=f"sqlite:///{(tmp_path / 'api.db').as_posix()}",
            scan_root_allowlist=(root,),
        ).with_overrides(**overrides)
        return TestClient(create_app(settings), base_url="http://127.0.0.1:8000")

    return make


@pytest.fixture
def client(make_client):
    with make_client() as c:
        yield c


def _register(client, root):
    r = client.post("/api/v1/repositories", json={"path": str(root / "proj")})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _wait(client, scan_id, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = client.get(f"/api/v1/scans/{scan_id}").json()
        if s["status"] not in ("queued", "running"):
            return s
        time.sleep(0.1)
    raise AssertionError("scan did not finish")


def test_health_and_headers(client):
    r = client.get("/api/v1/health")
    assert r.json() == {"status": "ok"}
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_register_rejects_out_of_root_T14(client, tmp_path):
    other = tmp_path / "elsewhere"
    other.mkdir()
    r = client.post("/api/v1/repositories", json={"path": str(other)})
    assert r.status_code == 403 and r.json()["error"]["code"] == "PATH_NOT_ALLOWED"
    r = client.post("/api/v1/repositories", json={"path": str(tmp_path / "missing")})
    assert r.json()["error"]["code"] == "PATH_NOT_FOUND"


def test_scan_requests_take_ids_not_paths(client):
    r = client.post("/api/v1/scans", json={"path": "/etc", "mode": "dir"})
    assert r.status_code == 422
    assert "/etc" not in r.text  # validation errors never echo input


def test_full_scan_flow_and_triage(client, root, fake_gitleaks):
    fake_gitleaks.records([raw_record(HEX64), raw_record(HEX64, RuleID="generic-api-key", File="docs/a.md", StartLine=9)])
    repo_id = _register(client, root)
    r = client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir"})
    assert r.status_code == 202 and r.json()["status"] == "queued"
    scan = _wait(client, r.json()["scan_id"])
    assert scan["status"] == "completed" and scan["policy_result"] == "fail"
    assert scan["scanner_version"] == "8.30.1" and scan["ruleset_digest"].startswith("sha256:")
    assert scan["severity_counts"]["critical"] == 1

    page = client.get("/api/v1/findings", params={"severity": "critical"}).json()
    assert page["total"] == 1
    f = page["items"][0]
    assert set(f) >= {"rule_id", "severity", "relative_path", "start_line", "status"}
    assert not ({"secret", "match", "line"} & set(f))

    detail = client.get(f"/api/v1/findings/{f['id']}").json()
    assert detail["remediation"]["key"] == "ROTATE_SIGNING_KEY" and detail["still_detected"]

    r = client.patch(f"/api/v1/findings/{f['id']}", json={"status": "acknowledged"})
    assert r.json()["status"] == "acknowledged" and r.json()["status_updated_at"]
    r = client.patch(f"/api/v1/findings/{f['id']}", json={"status": "suppressed"})
    assert r.status_code == 422  # suppression only via the reviewed endpoint
    events = client.get("/api/v1/audit-events", params={"entity_id": f["id"]}).json()
    assert events[0]["action"] == "finding.status_changed"

    # Acknowledged status carries over to the next scan; acknowledgement does not unblock.
    scan2 = _wait(client, client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir"}).json()["scan_id"])
    items = client.get(f"/api/v1/scans/{scan2['id']}/findings", params={"severity": "critical"}).json()["items"]
    assert items[0]["status"] == "acknowledged" and items[0]["blocking"]
    assert client.get(f"/api/v1/findings/{items[0]['id']}").json()["occurrences"] == 2


def test_filters_and_pagination(client, root, fake_gitleaks):
    fake_gitleaks.records([raw_record(HEX64, File=f"f{i}.env", StartLine=i + 1) for i in range(7)])
    repo_id = _register(client, root)
    _wait(client, client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir"}).json()["scan_id"])
    p1 = client.get("/api/v1/findings", params={"page_size": 5}).json()
    p2 = client.get("/api/v1/findings", params={"page_size": 5, "page": 2}).json()
    assert p1["total"] == 7 and len(p1["items"]) == 5 and len(p2["items"]) == 2
    assert client.get("/api/v1/findings", params={"rule_id": "nope"}).json()["total"] == 0
    assert client.get("/api/v1/findings", params={"severity": "bogus"}).status_code == 422
    scans = client.get("/api/v1/scans", params={"status": "completed", "mode": "dir"}).json()
    assert scans["total"] == 1


def test_failed_scan_reports_unknown_status(client, root, fake_gitleaks):
    fake_gitleaks.scenario("crash")
    repo_id = _register(client, root)
    scan = _wait(client, client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir"}).json()["scan_id"])
    assert scan["status"] == "failed" and scan["policy_result"] == "not_evaluated"
    assert scan["error_code"] == "SCANNER_ERROR" and "unknown" in scan["error_message"]
    assert "panic" not in str(scan)  # raw stderr never returned


def test_duplicate_scan_conflict_and_cancel(client, root, fake_gitleaks):
    fake_gitleaks.scenario("timeout")
    repo_id = _register(client, root)
    sid = client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir"}).json()["scan_id"]
    r = client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir"})
    assert r.status_code == 409
    time.sleep(0.5)
    assert client.post(f"/api/v1/scans/{sid}/cancel").status_code == 200
    assert _wait(client, sid)["status"] == "cancelled"


def test_suppression_requires_review_fields(client, root, fake_gitleaks):
    fake_gitleaks.records([raw_record(HEX64)])
    repo_id = _register(client, root)
    _wait(client, client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir"}).json()["scan_id"])
    fid = client.get("/api/v1/findings").json()["items"][0]["id"]
    bad = client.post("/api/v1/suppressions", json={"finding_id": fid, "reason": "short", "reviewer": "a", "expires_at": "2027-01-01"})
    assert bad.status_code == 422
    too_far = (date.today() + timedelta(days=500)).isoformat()
    assert client.post("/api/v1/suppressions", json={"finding_id": fid, "reason": "Reviewed synthetic value", "reviewer": "a", "expires_at": too_far}).status_code == 422
    ok = client.post("/api/v1/suppressions", json={"finding_id": fid, "reason": "Reviewed synthetic value", "reviewer": "alice",
                                                    "expires_at": (date.today() + timedelta(days=30)).isoformat()})
    assert ok.status_code == 201
    # Next scan honours the dashboard suppression -> pass
    scan = _wait(client, client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir"}).json()["scan_id"])
    assert scan["policy_result"] == "pass" and scan["suppressed_findings"] == 1
    # Deactivating restores blocking on the next scan.
    client.delete(f"/api/v1/suppressions/{ok.json()['id']}")
    scan = _wait(client, client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir"}).json()["scan_id"])
    assert scan["policy_result"] == "fail"


def test_metrics_overview(client, root, fake_gitleaks):
    fake_gitleaks.records([raw_record(HEX64)])
    repo_id = _register(client, root)
    _wait(client, client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir"}).json()["scan_id"])
    m = client.get("/api/v1/metrics/overview").json()
    assert m["repositories"] == 1 and m["scans_completed"] == 1
    assert m["open_findings"] == 1 and m["blocking_open_findings"] == 1
    assert m["severity_counts"]["critical"] == 1 and len(m["trend"]) == 1


def test_rules_and_system_endpoints(client):
    rules = client.get("/api/v1/rules").json()
    assert rules["ruleset_digest"].startswith("sha256:")
    assert any(r["rule_id"] == "web3-evm-private-key-assignment" for r in rules["rules"])
    status = client.get("/api/v1/system/status").json()
    assert status["scanner"]["available"] and status["auth_required"] is False


def test_csrf_protections(client, root):
    r = client.post("/api/v1/repositories", content="path=/x", headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 415
    r = client.post("/api/v1/repositories", json={"path": str(root / "proj")}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN_ORIGIN"
    r = client.post("/api/v1/repositories", json={"path": str(root / "proj")}, headers={"Origin": "http://127.0.0.1:5173"})
    assert r.status_code == 201


def test_dns_rebinding_host_rejected(client):
    assert client.get("/api/v1/health", headers={"Host": "attacker.example"}).status_code == 400


def test_api_token_mode(make_client):
    with make_client(api_token="t0ken-for-tests") as c:
        assert c.get("/api/v1/health").status_code == 200
        assert c.get("/api/v1/findings").status_code == 401
        assert c.get("/api/v1/findings", headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert c.get("/api/v1/findings", headers={"Authorization": "Bearer t0ken-for-tests"}).status_code == 200


def test_rate_limit_in_remote_mode(make_client):
    with make_client(api_token="tok", rate_limit_per_minute=3) as c:
        codes = [c.get("/api/v1/health").status_code for _ in range(5)]
        assert codes[:3] == [200, 200, 200] and codes[-1] == 429


def test_refuses_remote_bind_without_auth():
    with pytest.raises(SecretSentinelError):
        validate_startup(Settings(host="0.0.0.0"))
    validate_startup(Settings(host="0.0.0.0", allow_remote=True, api_token="x"))
    validate_startup(Settings())


def test_unknown_routes_and_internal_errors_are_generic(client):
    r = client.get("/api/v1/nope")
    assert r.status_code == 404 and r.json()["error"]["code"] == "NOT_FOUND"


def test_delete_repository_cascades(client, root, fake_gitleaks):
    fake_gitleaks.records([raw_record(HEX64)])
    repo_id = _register(client, root)
    _wait(client, client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir"}).json()["scan_id"])
    assert client.delete(f"/api/v1/repositories/{repo_id}").status_code == 204
    assert client.get("/api/v1/findings", params={"latest_only": False}).json()["total"] == 0


def test_ingest_requires_token_and_strict_schema(make_client):
    report = {
        "schema": "secretsentinel-report/v1",
        "tool": {"name": "SecretSentinel", "version": "1.0.0", "scanner": "gitleaks", "scanner_version": "8.30.1",
                 "ruleset_version": "1.0.0", "ruleset_digest": "sha256:ab", "policy_digest": "sha256:cd"},
        "scan": {"target": "repo", "mode": "git", "scope": "full-history", "status": "completed", "error_code": None,
                 "error_message": None, "policy_result": "fail", "fail_on": "high", "commit_sha": "a" * 40,
                 "started_at": None, "finished_at": None, "total_findings": 1, "blocking_findings": 1,
                 "suppressed_findings": 0, "severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0}, "warnings": []},
        "findings": [{"fingerprint": "ss1:" + "0" * 32, "rule_id": "web3-evm-private-key-assignment", "title": "t",
                      "rule_family": "web3-signing-key", "severity": "critical", "confidence": "high", "requirement": "W3-01",
                      "relative_path": "a.env", "start_line": 1, "end_line": 1, "start_column": 1, "commit_sha": "b" * 40,
                      "entropy": 3.8, "sources": ["git"], "also_matched": [], "status": "open", "suppression_id": None,
                      "blocking": True, "remediation_key": "ROTATE_SIGNING_KEY"}],
    }
    with make_client() as c:
        assert c.post("/api/v1/ingest/scan-summary", json=report).status_code == 404  # disabled
    with make_client(ingest_token="ingest-secret") as c:
        assert c.post("/api/v1/ingest/scan-summary", json=report).status_code == 401
        h = {"Authorization": "Bearer ingest-secret"}
        raw = dict(report, findings=[dict(report["findings"][0], Secret=HEX64)])
        assert c.post("/api/v1/ingest/scan-summary", json=raw, headers=h).status_code == 422  # raw fields rejected
        r = c.post("/api/v1/ingest/scan-summary", json=report, headers=h)
        assert r.status_code == 201
        scan = c.get(f"/api/v1/scans/{r.json()['scan_id']}").json()
        assert scan["mode"] == "ci" and scan["source"] == "ingest" and scan["blocking_findings"] == 1
