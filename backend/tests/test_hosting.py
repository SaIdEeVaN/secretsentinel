"""Hosted (Render) deployment settings: Postgres URLs, secrets never printed,
trusted host from RENDER_EXTERNAL_HOSTNAME, HSTS and status flags."""

import pytest
from fastapi.testclient import TestClient

from secretsentinel.cli import main
from secretsentinel.core.config import Settings
from secretsentinel.database import normalize_db_url, redact_db_url
from secretsentinel.main import create_app

PG = "postgres://ssuser:Sup3rS3cretPw@dpg-example-a.singapore-postgres.render.com/secretsentinel"


@pytest.mark.parametrize(
    "url,expected",
    [
        ("postgres://u:p@h/db", "postgresql+psycopg://u:p@h/db"),
        ("postgresql://u:p@h:5432/db", "postgresql+psycopg://u:p@h:5432/db"),
        ("postgresql+psycopg://u:p@h/db", "postgresql+psycopg://u:p@h/db"),
        ("sqlite:///x.db", "sqlite:///x.db"),
    ],
)
def test_normalize_db_url(url, expected):
    assert normalize_db_url(url) == expected


def test_db_password_is_never_printed(monkeypatch, capsys):
    assert "Sup3rS3cretPw" not in redact_db_url(PG) and "***" in redact_db_url(PG)
    assert "Sup3rS3cretPw" not in repr(Settings(db_url=PG))
    monkeypatch.setenv("DB_URL", PG)
    main(["doctor", "--gitleaks", "/nonexistent"])
    main(["db", "path"])
    assert "Sup3rS3cretPw" not in capsys.readouterr().out


def test_render_hostname_is_trusted():
    s = Settings.from_env({"RENDER_EXTERNAL_HOSTNAME": "secretsentinel-dashboard.onrender.com"})
    assert "secretsentinel-dashboard.onrender.com" in s.trusted_hosts
    assert "127.0.0.1" in s.trusted_hosts


def test_hosted_mode_headers_and_flags(tmp_path):
    s = Settings(
        host="0.0.0.0", allow_remote=True, api_token="viewer-token", ingest_token="upload-token",
        db_url=f"sqlite:///{(tmp_path / 'h.db').as_posix()}",
        trusted_hosts=("dash.onrender.com",),
    )
    with TestClient(create_app(s), base_url="https://dash.onrender.com") as c:
        r = c.get("/api/v1/system/status", headers={"Authorization": "Bearer viewer-token"})
        assert r.status_code == 200
        body = r.json()
        assert body["hosted"] and body["ingest_enabled"] and not body["local_scanning_enabled"]
        assert r.headers["strict-transport-security"].startswith("max-age=")
        assert c.get("/api/v1/system/status").status_code == 401
        # Same-origin browser writes are accepted; the upload token cannot read the dashboard.
        assert c.get("/api/v1/scans", headers={"Authorization": "Bearer upload-token"}).status_code == 401
        assert c.get("/api/v1/health", headers={"Host": "evil.example"}).status_code == 400
