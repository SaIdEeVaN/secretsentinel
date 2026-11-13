"""FastAPI contract, validation, security middleware and triage workflow."""

import os
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
    # Set SECRETSENTINEL_TEST_DATABASE_URL to run this suite against Postgres
    # (the hosted deployment's database); each client starts from an empty schema.
    pg_url = os.environ.get("SECRETSENTINEL_TEST_DATABASE_URL")

    def make(**overrides):
        db_url = f"sqlite:///{(tmp_path / 'api.db').as_posix()}"
        if pg_url:
            from sqlalchemy import create_engine

            from secretsentinel.database import normalize_db_url, reset_engine
            from secretsentinel.models import Base

            reset_engine()
            engine = create_engine(normalize_db_url(pg_url))
            Base.metadata.drop_all(engine)
            engine.dispose()
            db_url = pg_url
        settings = Settings(
            gitleaks_path=fake_gitleaks.path,
            db_url=db_url,
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


def test_finding_facets_match_the_list(client, root, fake_gitleaks):
    fake_gitleaks.records([raw_record(HEX64), raw_record(HEX64, RuleID="generic-api-key", File="docs/a.md", StartLine=9)])
    repo_id = _register(client, root)
    _wait(client, client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir"}).json()["scan_id"])

    facets = client.get("/api/v1/findings/facets").json()
    assert facets["total"] == client.get("/api/v1/findings").json()["total"] == 2
    assert facets["severity"]["critical"] == 1 and sum(facets["severity"].values()) == 2
    assert facets["status"] == {"open": 2, "acknowledged": 0, "resolved": 0, "suppressed": 0}

    # Each dimension ignores its own filter and applies the others.
    crit = client.get("/api/v1/findings/facets", params={"severity": "critical"}).json()
    assert crit["total"] == 1
    assert sum(crit["severity"].values()) == 2
    assert crit["status"]["open"] == 1

    f = client.get("/api/v1/findings", params={"severity": "critical"}).json()["items"][0]
    assert client.patch(f"/api/v1/findings/{f['id']}", json={"status": "acknowledged"}).status_code == 200
    ack = client.get("/api/v1/findings/facets", params={"status": "acknowledged"}).json()
    assert ack["total"] == 1 and ack["severity"]["critical"] == 1
    assert ack["status"]["open"] == 1 and ack["status"]["acknowledged"] == 1

    assert client.get("/api/v1/findings/facets", params={"severity": "bogus"}).status_code == 422
    # "facets" is a route, never a finding id
    assert client.get("/api/v1/findings/facets").status_code == 200


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


def test_finding_detail_explains_its_suppression(client, root, fake_gitleaks):
    fake_gitleaks.records([raw_record(HEX64)])
    repo_id = _register(client, root)
    _wait(client, client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir"}).json()["scan_id"])
    fid = client.get("/api/v1/findings").json()["items"][0]["id"]
    assert client.get(f"/api/v1/findings/{fid}").json()["suppression"] is None
    expires = (date.today() + timedelta(days=30)).isoformat()
    sup = client.post("/api/v1/suppressions", json={"finding_id": fid, "reason": "Reviewed synthetic value", "reviewer": "alice",
                                                     "expires_at": expires})
    assert sup.status_code == 201
    info = client.get(f"/api/v1/findings/{fid}").json()["suppression"]
    assert info == {"id": f"db-{sup.json()['id'][:8]}", "origin": "dashboard", "reason": "Reviewed synthetic value",
                    "reviewer": "alice", "expires_at": expires, "active": True}
    # the next scan's copy of the finding is suppressed by the same entry
    scan = _wait(client, client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir"}).json()["scan_id"])
    again = client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"][0]
    assert client.get(f"/api/v1/findings/{again['id']}").json()["suppression"]["reviewer"] == "alice"


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


@pytest.mark.parametrize("format", ["json", "csv", "sarif"])
def test_export_contains_only_sanitized_findings(client, root, fake_gitleaks, format):
    fake_gitleaks.records([raw_record(HEX64, File="=SUM(1).env")])
    repo_id = _register(client, root)
    scan = _wait(client, client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir"}).json()["scan_id"])
    response = client.get(f"/api/v1/scans/{scan['id']}/export", params={"format": format})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert f"secretsentinel-{scan['id']}.{format}" in response.headers["content-disposition"]
    assert HEX64 not in response.text and str(root) not in response.text
    assert '"Secret"' not in response.text and '"Match"' not in response.text
    if format == "json":
        report = response.json()
        assert report["schema"] == "secretsentinel-report/v1"
        assert report["scan"]["policy_result"] == "fail"
        assert report["scan"]["total_findings"] == len(report["findings"]) == 1
        assert report["findings"][0]["blocking"]
    elif format == "sarif":
        assert response.json()["version"] == "2.1.0"
        assert len(response.json()["runs"][0]["results"]) == 1
    else:
        assert "'=SUM(1).env" in response.text  # spreadsheet formula is neutralized


def test_export_includes_findings_beyond_api_page_size(client, root, fake_gitleaks):
    fake_gitleaks.records([raw_record(HEX64, File=f"f{i}.env") for i in range(205)])
    repo_id = _register(client, root)
    scan = _wait(client, client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir"}).json()["scan_id"])
    report = client.get(f"/api/v1/scans/{scan['id']}/export").json()
    assert len(report["findings"]) == report["scan"]["total_findings"] == 205


def test_export_rejects_failed_and_active_scans(client, root, fake_gitleaks):
    repo_id = _register(client, root)
    fake_gitleaks.scenario("crash")
    scan = _wait(client, client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir"}).json()["scan_id"])
    assert client.get(f"/api/v1/scans/{scan['id']}/export").status_code == 409
    assert client.get(f"/api/v1/scans/{scan['id']}/export?format=raw").status_code == 422
    assert client.get("/api/v1/scans/missing/export").status_code == 404
    fake_gitleaks.scenario("timeout")
    sid = client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir"}).json()["scan_id"]
    assert client.get(f"/api/v1/scans/{sid}/export").status_code == 409
    client.post(f"/api/v1/scans/{sid}/cancel")
    assert _wait(client, sid)["status"] == "cancelled"


@pytest.mark.parametrize("threshold,blocking", [("high", True), ("none", False)])
def test_deactivating_suppression_restores_blocking_decision(client, root, fake_gitleaks, threshold, blocking):
    fake_gitleaks.records([raw_record(HEX64)])
    repo_id = _register(client, root)
    scan = _wait(client, client.post("/api/v1/scans", json={"repository_id": repo_id, "mode": "dir", "fail_on": threshold}).json()["scan_id"])
    finding = client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"][0]
    suppression = client.post("/api/v1/suppressions", json={
        "finding_id": finding["id"], "reason": "Reviewed synthetic test fixture", "reviewer": "reviewer",
        "expires_at": (date.today() + timedelta(days=30)).isoformat(),
    })
    assert suppression.status_code == 201
    assert client.get(f"/api/v1/scans/{scan['id']}/export").status_code == 409
    assert client.delete(f"/api/v1/suppressions/{suppression.json()['id']}").status_code == 200
    updated = client.get(f"/api/v1/findings/{finding['id']}").json()
    assert updated["status"] == "open" and updated["blocking"] is blocking
    assert updated["suppression_id"] is None
    report = client.get(f"/api/v1/scans/{scan['id']}/export").json()
    assert report["findings"][0]["blocking"] is blocking


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


def test_ingest_reports_new_blocking_findings(make_client):
    tool = {"name": "SecretSentinel", "version": "1.0.0", "scanner": "gitleaks", "scanner_version": "8.30.1",
            "ruleset_version": "1.0.0", "ruleset_digest": "sha256:ab", "policy_digest": "sha256:cd"}

    def finding(path, blocking=True):
        return {"fingerprint": "ss1:" + "0" * 32, "rule_id": "web3-evm-private-key-assignment", "title": "t",
                "rule_family": "web3-signing-key", "severity": "critical" if blocking else "low", "confidence": "high",
                "requirement": "W3-01", "relative_path": path, "start_line": 1, "end_line": 1, "start_column": 1,
                "commit_sha": "b" * 40, "entropy": 3.8, "sources": ["git"], "also_matched": [], "status": "open",
                "suppression_id": None, "blocking": blocking, "remediation_key": "ROTATE_SIGNING_KEY"}

    def report(findings, name="acme/app"):
        blocking = sum(1 for f in findings if f["blocking"])
        return {
            "schema": "secretsentinel-report/v1", "tool": tool, "repository_name": name, "findings": findings,
            "scan": {"target": "repo", "mode": "git", "scope": "full-history", "status": "completed", "error_code": None,
                     "error_message": None, "policy_result": "fail" if blocking else "pass", "fail_on": "high",
                     "commit_sha": "a" * 40, "started_at": None, "finished_at": None, "total_findings": len(findings),
                     "blocking_findings": blocking, "suppressed_findings": 0,
                     "severity_counts": {"critical": blocking, "high": 0, "medium": 0, "low": len(findings) - blocking},
                     "warnings": []},
        }

    h = {"Authorization": "Bearer ingest-secret"}
    with make_client(ingest_token="ingest-secret") as c:
        first = c.post("/api/v1/ingest/scan-summary", json=report([finding("a.env"), finding("docs/n.md", False)]), headers=h).json()
        assert (first["new_findings"], first["new_blocking_findings"]) == (2, 1)  # first upload: everything is new
        again = c.post("/api/v1/ingest/scan-summary", json=report([finding("a.env"), finding("docs/n.md", False)]), headers=h).json()
        assert (again["new_findings"], again["new_blocking_findings"]) == (0, 0)  # unchanged: no alert
        more = c.post("/api/v1/ingest/scan-summary", json=report([finding("a.env"), finding("b.env")]), headers=h).json()
        assert (more["new_findings"], more["new_blocking_findings"]) == (1, 1)  # one new blocking finding
        other = c.post("/api/v1/ingest/scan-summary", json=report([finding("a.env")], name="acme/other"), headers=h).json()
        assert other["new_blocking_findings"] == 1  # history is per repository


_CI_TOOL = {"name": "SecretSentinel", "version": "1.0.0", "scanner": "gitleaks", "scanner_version": "8.30.1",
            "ruleset_version": "1.0.0", "ruleset_digest": "sha256:ab", "policy_digest": "sha256:cd"}


def _ci_finding(path, line=1, severity="critical", blocking=True, status="open"):
    return {"fingerprint": "ss1:" + "0" * 32, "rule_id": "web3-evm-private-key-assignment", "title": "t",
            "rule_family": "web3-signing-key", "severity": severity, "confidence": "high", "requirement": "W3-01",
            "relative_path": path, "start_line": line, "end_line": line, "start_column": 1, "commit_sha": "b" * 40,
            "entropy": 3.8, "sources": ["git"], "also_matched": [], "status": status,
            "suppression_id": None, "blocking": blocking, "remediation_key": "ROTATE_SIGNING_KEY"}


def _ci_report(findings, name="acme/app"):
    blocking = sum(1 for f in findings if f["blocking"])
    return {
        "schema": "secretsentinel-report/v1", "tool": _CI_TOOL, "repository_name": name, "findings": findings,
        "scan": {"target": "repo", "mode": "git", "scope": "full-history", "status": "completed", "error_code": None,
                 "error_message": None, "policy_result": "fail" if blocking else "pass", "fail_on": "high",
                 "commit_sha": "a" * 40, "started_at": None, "finished_at": None, "total_findings": len(findings),
                 "blocking_findings": blocking, "suppressed_findings": 0,
                 "severity_counts": {"critical": blocking, "high": 0, "medium": 0, "low": len(findings) - blocking},
                 "warnings": []},
    }


def _suppress_via_dashboard(c, scan_id, path, reviewer="alice", days=30):
    items = c.get(f"/api/v1/scans/{scan_id}/findings").json()["items"]
    finding = next(f for f in items if f["relative_path"] == path)
    r = c.post("/api/v1/suppressions", json={
        "finding_id": finding["id"], "reason": "Reviewed: synthetic value in a fixture", "reviewer": reviewer,
        "expires_at": (date.today() + timedelta(days=days)).isoformat()})
    assert r.status_code == 201, r.text
    return r.json()


def test_dashboard_suppression_applies_to_the_next_ci_upload(make_client):
    h = {"Authorization": "Bearer ingest-secret"}
    with make_client(ingest_token="ingest-secret") as c:
        first = c.post("/api/v1/ingest/scan-summary", json=_ci_report([_ci_finding("a.env"), _ci_finding("b.env")]), headers=h).json()
        assert first["new_blocking_findings"] == 2
        sup = _suppress_via_dashboard(c, first["scan_id"], "a.env")
        again = c.post("/api/v1/ingest/scan-summary", json=_ci_report([_ci_finding("a.env"), _ci_finding("b.env")]), headers=h).json()
        scan = c.get(f"/api/v1/scans/{again['scan_id']}").json()
        assert (scan["blocking_findings"], scan["suppressed_findings"], scan["policy_result"]) == (1, 1, "fail")
        items = c.get(f"/api/v1/scans/{again['scan_id']}/findings").json()["items"]
        by_path = {f["relative_path"]: f for f in items}
        assert by_path["a.env"]["status"] == "suppressed" and not by_path["a.env"]["blocking"]
        assert by_path["b.env"]["status"] == "open" and by_path["b.env"]["blocking"]
        detail = c.get(f"/api/v1/findings/{by_path['a.env']['id']}").json()["suppression"]
        assert detail["origin"] == "dashboard" and detail["reviewer"] == "alice"
        assert any("covered by dashboard suppressions" in w for w in scan["warnings"])

        # Suppressing the last blocking finding makes the uploaded scan pass.
        _suppress_via_dashboard(c, again["scan_id"], "b.env")
        last = c.post("/api/v1/ingest/scan-summary", json=_ci_report([_ci_finding("a.env"), _ci_finding("b.env")]), headers=h).json()
        scan = c.get(f"/api/v1/scans/{last['scan_id']}").json()
        assert (scan["blocking_findings"], scan["suppressed_findings"], scan["policy_result"]) == (0, 2, "pass")

        # Deactivating the suppression restores the finding on the next upload.
        c.delete(f"/api/v1/suppressions/{sup['id']}")
        back = c.post("/api/v1/ingest/scan-summary", json=_ci_report([_ci_finding("a.env"), _ci_finding("b.env")]), headers=h).json()
        scan = c.get(f"/api/v1/scans/{back['scan_id']}").json()
        assert (scan["blocking_findings"], scan["suppressed_findings"], scan["policy_result"]) == (1, 1, "fail")


def test_suppressed_finding_does_not_raise_the_new_blocking_alert(make_client):
    """A reviewed finding that moves a few lines within the same commit stays suppressed and is not an alert."""
    h = {"Authorization": "Bearer ingest-secret"}
    with make_client(ingest_token="ingest-secret") as c:
        first = c.post("/api/v1/ingest/scan-summary", json=_ci_report([_ci_finding("a.env", line=1)]), headers=h).json()
        _suppress_via_dashboard(c, first["scan_id"], "a.env")
        moved = c.post("/api/v1/ingest/scan-summary", json=_ci_report([_ci_finding("a.env", line=7)]), headers=h).json()
        assert (moved["new_findings"], moved["new_blocking_findings"]) == (1, 0)
        assert c.get(f"/api/v1/scans/{moved['scan_id']}").json()["policy_result"] == "pass"


def test_dashboard_suppressions_stay_inside_their_repository_and_expire(make_client):
    h = {"Authorization": "Bearer ingest-secret"}
    with make_client(ingest_token="ingest-secret") as c:
        first = c.post("/api/v1/ingest/scan-summary", json=_ci_report([_ci_finding("a.env")]), headers=h).json()
        sup = _suppress_via_dashboard(c, first["scan_id"], "a.env")
        # Another repository with the same rule, path and commit is not covered.
        other = c.post("/api/v1/ingest/scan-summary", json=_ci_report([_ci_finding("a.env")], name="acme/other"), headers=h).json()
        assert other["new_blocking_findings"] == 1
        assert c.get(f"/api/v1/scans/{other['scan_id']}").json()["blocking_findings"] == 1

        # An expired suppression is ignored, with a constant warning (no values).
        from sqlalchemy import update

        from secretsentinel.database import session_scope
        from secretsentinel.models import Suppression

        with session_scope() as session:
            session.execute(update(Suppression).where(Suppression.id == sup["id"]).values(expires_at=date.today() - timedelta(days=1)))
        again = c.post("/api/v1/ingest/scan-summary", json=_ci_report([_ci_finding("a.env")]), headers=h).json()
        scan = c.get(f"/api/v1/scans/{again['scan_id']}").json()
        assert scan["blocking_findings"] == 1 and scan["policy_result"] == "fail"
        assert any("ignored: expired" in w for w in scan["warnings"])


def test_db_sessions_commit_before_the_response_is_sent(client):
    """Regression: request-scoped yield deps commit after the response is sent,
    so a browser reading right after a write saw stale data (found by the E2E
    suite on GitHub runners). TestClient cannot observe that race, so assert
    the dependency scope structurally for every route."""
    from fastapi.routing import APIRoute

    from secretsentinel.api import (
        routes_attestations, routes_findings, routes_ingest, routes_metrics, routes_repositories, routes_scans,
    )
    from secretsentinel.api.deps import get_db

    def walk(dependant):
        for dep in dependant.dependencies:
            yield dep
            yield from walk(dep)

    checked = 0
    modules = (routes_attestations, routes_findings, routes_ingest, routes_metrics, routes_repositories, routes_scans)
    for route in (r for m in modules for r in m.router.routes):
        if isinstance(route, APIRoute):
            for dep in walk(route.dependant):
                if dep.call is get_db:
                    assert dep.scope == "function", f"{route.path} uses a request-scoped DB session"
                    checked += 1
    assert checked >= 15
