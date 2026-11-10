"""scripts/upload_report.py: retries while a free-tier host wakes up, strict
URL rules, and the token is never printed."""

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "upload_report.py"
spec = importlib.util.spec_from_file_location("upload_report", SCRIPT)
upload_report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upload_report)

TOKEN = "upload-token-for-tests"


@pytest.fixture
def report(tmp_path):
    p = tmp_path / "report.json"
    p.write_text(json.dumps({"schema": "secretsentinel-report/v1", "tool": {}, "findings": [],
                             "scan": {"status": "completed", "policy_result": "pass", "blocking_findings": 0, "total_findings": 0}}))
    return p


@pytest.fixture
def server():
    state = {"requests": [], "responses": []}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["requests"].append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
            code, payload = state["responses"].pop(0) if state["responses"] else (201, {"scan_id": "s1", "status": "completed"})
            data = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    state["url"] = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield state
    httpd.shutdown()


def test_retries_while_waking_then_uploads(server, report, monkeypatch, capsys):
    monkeypatch.setenv("SECRETSENTINEL_INGEST_TOKEN", TOKEN)
    server["responses"] = [(503, {}), (502, {})]
    rc = upload_report.main([str(report), "--url", server["url"], "--repository", "acme/app", "--wait", "0.01"])
    assert rc == 0 and len(server["requests"]) == 3
    req = server["requests"][-1]
    assert req["path"] == "/api/v1/ingest/scan-summary"
    assert req["auth"] == f"Bearer {TOKEN}"
    assert req["body"]["repository_name"] == "acme/app"
    out = capsys.readouterr()
    assert "Uploaded" in out.out and TOKEN not in out.out + out.err


def test_rejected_token_fails_without_echoing_it(server, report, monkeypatch, capsys):
    monkeypatch.setenv("SECRETSENTINEL_INGEST_TOKEN", TOKEN)
    server["responses"] = [(401, {"error": {"code": "UNAUTHORIZED", "message": "Authentication is required."}})]
    assert upload_report.main([str(report), "--url", server["url"], "--wait", "0.01"]) == 1
    out = capsys.readouterr()
    assert "UNAUTHORIZED" in out.err and TOKEN not in out.out + out.err
    assert len(server["requests"]) == 1  # 401 is not retried


@pytest.mark.parametrize("url", ["http://dashboard.example.com", "ftp://x", "https://"])
def test_refuses_insecure_or_bad_urls(report, monkeypatch, url):
    monkeypatch.setenv("SECRETSENTINEL_INGEST_TOKEN", TOKEN)
    assert upload_report.main([str(report), "--url", url]) == 1


def test_refuses_non_report_files_and_missing_token(tmp_path, server, monkeypatch):
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps([{"RuleID": "x", "Secret": "nope"}]))  # a raw Gitleaks report
    monkeypatch.setenv("SECRETSENTINEL_INGEST_TOKEN", TOKEN)
    assert upload_report.main([str(raw), "--url", server["url"]]) == 1
    assert server["requests"] == []
    monkeypatch.delenv("SECRETSENTINEL_INGEST_TOKEN")
    assert upload_report.main([str(raw), "--url", server["url"]]) == 1


def test_gives_up_when_unreachable(report, monkeypatch):
    monkeypatch.setenv("SECRETSENTINEL_INGEST_TOKEN", TOKEN)
    assert upload_report.main([str(report), "--url", "http://127.0.0.1:9", "--attempts", "2", "--wait", "0.01", "--timeout", "2"]) == 1
