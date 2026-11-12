"""scripts/token_expiry.py: warns/fails ahead of expiry and never prints the token."""

import importlib.util
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "token_expiry.py"
spec = importlib.util.spec_from_file_location("token_expiry", SCRIPT)
token_expiry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(token_expiry)

TOKEN = "fine-grained-token-for-tests"


@pytest.mark.parametrize(
    "value",
    ["2030-01-02 03:04:05 UTC", "2030-01-02 03:04:05 +0000", "2030-01-02T03:04:05+00:00"],
)
def test_parses_githubs_expiry_formats(value):
    assert token_expiry.parse_expiry(value) == datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def test_unknown_format_is_none():
    assert token_expiry.parse_expiry("next tuesday") is None


@pytest.fixture
def github():
    state = {"status": 200, "header": None, "auth": []}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            state["auth"].append(self.headers.get("Authorization"))
            self.send_response(state["status"])
            if state["header"]:
                self.send_header(token_expiry.HEADER, state["header"])
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    state["api"] = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield state
    httpd.shutdown()


def _in(days):
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S UTC")


@pytest.mark.parametrize(
    ("days", "rc", "marker"),
    [(60, 0, "day(s) left"), (10, 0, "::warning"), (3, 1, "::error"), (-1, 1, "::error")],
)
def test_thresholds(github, monkeypatch, capsys, days, rc, marker):
    monkeypatch.setenv("TOKEN", TOKEN)
    github["header"] = _in(days)
    assert token_expiry.main(["--api", github["api"]]) == rc
    out = capsys.readouterr().out
    assert marker in out and TOKEN not in out
    assert github["auth"] == [f"Bearer {TOKEN}"]


def test_rejected_token_fails(github, monkeypatch, capsys):
    monkeypatch.setenv("TOKEN", TOKEN)
    github["status"] = 401
    assert token_expiry.main(["--api", github["api"]]) == 1
    assert "no longer accepts" in capsys.readouterr().out


def test_token_without_expiry_passes(github, monkeypatch, capsys):
    monkeypatch.setenv("TOKEN", TOKEN)
    assert token_expiry.main(["--api", github["api"]]) == 0
    assert "no expiry date" in capsys.readouterr().out


def test_unset_token_is_not_checked(github, monkeypatch, capsys):
    monkeypatch.delenv("TOKEN", raising=False)
    assert token_expiry.main(["--api", github["api"]]) == 0
    assert github["auth"] == []


def test_unreachable_api_only_warns(monkeypatch, capsys):
    monkeypatch.setenv("TOKEN", TOKEN)
    assert token_expiry.main(["--api", "http://127.0.0.1:9"]) == 0
    out = capsys.readouterr().out
    assert "::warning" in out and TOKEN not in out
