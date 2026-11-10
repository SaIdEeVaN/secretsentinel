"""Application settings.

Settings come ONLY from real environment variables or from an env file passed
explicitly (``secretsentinel serve --env-file .env``). SecretSentinel never
auto-loads a ``.env`` from the current directory, because when the CLI runs
inside a scanned repository that file is untrusted input and could, for
example, point GITLEAKS_PATH at a malicious executable (invariant S4).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Mapping

SEVERITY_LEVELS = ("critical", "high", "medium", "low")
FAIL_ON_LEVELS = SEVERITY_LEVELS + ("none",)


def default_data_dir() -> Path:
    return Path.home() / ".secretsentinel"


def default_db_url() -> str:
    return f"sqlite:///{(default_data_dir() / 'secretsentinel.db').as_posix()}"


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(value: str | None, default: int, minimum: int = 0, maximum: int | None = None) -> int:
    if value is None or value.strip() == "":
        return default
    try:
        parsed = int(value)
    except ValueError:
        raise ValueError("expected an integer setting") from None
    if parsed < minimum or (maximum is not None and parsed > maximum):
        raise ValueError("integer setting out of range")
    return parsed


def _split_list(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    parts = re.split(r"[,;]" if os.name == "nt" else r"[,;:]", value)
    return tuple(p.strip() for p in parts if p.strip())


@dataclass(frozen=True)
class Settings:
    app_env: str = "development"
    host: str = "127.0.0.1"
    port: int = 8000
    db_url: str = field(default_factory=default_db_url)
    gitleaks_path: str = "gitleaks"
    git_path: str = "git"
    scanner_timeout_seconds: int = 120
    max_scan_file_mb: int = 10
    max_repo_mb: int = 2048
    max_repo_files: int = 250_000
    scan_root_allowlist: tuple[Path, ...] = ()
    log_level: str = "INFO"
    enable_blockchain: bool = False
    cors_origins: tuple[str, ...] = ("http://127.0.0.1:5173", "http://localhost:5173")
    trusted_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "::1")
    api_token: str | None = field(default=None, repr=False)
    ingest_token: str | None = field(default=None, repr=False)
    allow_remote: bool = False
    rate_limit_per_minute: int = 300
    max_concurrent_scans: int = 1
    default_fail_on: str = "high"
    scan_retention_days: int = 0
    # P2 (optional blockchain attestations)
    sepolia_rpc_url: str | None = field(default=None, repr=False)
    attestation_signer_key_reference: str | None = field(default=None, repr=False)
    attestation_contract_address: str | None = None
    attestation_chain_id: int = 11155111
    trusted_attestation_signers: tuple[str, ...] = ()

    @property
    def is_loopback(self) -> bool:
        return self.host in {"127.0.0.1", "localhost", "::1"}

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if environ is None else environ
        roots = tuple(
            Path(p).expanduser().resolve() for p in _split_list(env.get("SCAN_ROOT_ALLOWLIST"))
        )
        fail_on = (env.get("FAIL_ON") or "high").strip().lower()
        if fail_on not in FAIL_ON_LEVELS:
            raise ValueError("FAIL_ON must be one of critical|high|medium|low|none")
        cors = env.get("CORS_ORIGINS")
        hosts = env.get("TRUSTED_HOSTS")
        settings = cls(
            app_env=env.get("APP_ENV", "development"),
            host=env.get("HOST", "127.0.0.1"),
            port=_int(env.get("PORT"), 8000, 1, 65535),
            db_url=env.get("DB_URL") or default_db_url(),
            gitleaks_path=env.get("GITLEAKS_PATH") or "gitleaks",
            git_path=env.get("GIT_PATH") or "git",
            scanner_timeout_seconds=_int(env.get("SCANNER_TIMEOUT_SECONDS"), 120, 1, 86_400),
            max_scan_file_mb=_int(env.get("MAX_SCAN_FILE_MB"), 10, 1, 10_000),
            max_repo_mb=_int(env.get("MAX_REPO_MB"), 2048, 1, 1_000_000),
            max_repo_files=_int(env.get("MAX_REPO_FILES"), 250_000, 1, 50_000_000),
            scan_root_allowlist=roots,
            log_level=(env.get("LOG_LEVEL") or "INFO").upper(),
            enable_blockchain=_bool(env.get("ENABLE_BLOCKCHAIN")),
            cors_origins=tuple(p.strip() for p in cors.split(",") if p.strip()) if cors else cls.cors_origins,
            trusted_hosts=tuple(p.strip() for p in hosts.split(",") if p.strip()) if hosts else cls.trusted_hosts,
            api_token=env.get("API_TOKEN") or None,
            ingest_token=env.get("INGEST_TOKEN") or None,
            allow_remote=_bool(env.get("ALLOW_REMOTE")),
            rate_limit_per_minute=_int(env.get("RATE_LIMIT_PER_MINUTE"), 300, 1, 1_000_000),
            max_concurrent_scans=_int(env.get("MAX_CONCURRENT_SCANS"), 1, 1, 16),
            default_fail_on=fail_on,
            scan_retention_days=_int(env.get("SCAN_RETENTION_DAYS"), 0, 0, 36_500),
            sepolia_rpc_url=env.get("SEPOLIA_RPC_URL") or None,
            attestation_signer_key_reference=env.get("ATTESTATION_SIGNER_KEY_REFERENCE") or None,
            attestation_contract_address=env.get("ATTESTATION_CONTRACT_ADDRESS") or None,
            attestation_chain_id=_int(env.get("ATTESTATION_CHAIN_ID"), 11155111, 1),
            trusted_attestation_signers=tuple(
                s.lower() for s in _split_list(env.get("TRUSTED_ATTESTATION_SIGNERS"))
            ),
        )
        return settings

    def with_overrides(self, **kwargs) -> "Settings":
        valid = {f.name for f in fields(self)}
        return replace(self, **{k: v for k, v in kwargs.items() if k in valid})


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse a simple KEY=VALUE env file (comments and blank lines ignored)."""
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if re.fullmatch(r"[A-Z_][A-Z0-9_]*", key):
            values[key] = value
    return values


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings.from_env()
    return _settings


def set_settings(settings: Settings | None) -> None:
    """Override the process-wide settings (used by the CLI and tests)."""
    global _settings
    _settings = settings
