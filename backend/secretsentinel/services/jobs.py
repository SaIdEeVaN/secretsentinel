"""Local background scan queue (in-process thread pool).

Scan requests return immediately (HTTP 202); a worker runs the scan and
writes the sanitized outcome to SQLite. Paths are re-validated against the
allowlist when the job STARTS, not only at registration time, so a directory
swapped for a symlink in between is still rejected.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from ..core.config import Settings
from ..core.errors import ErrorCode, SecretSentinelError
from ..core.log import log_event
from ..core.security import canonicalize_existing_dir, ensure_within_allowed_roots
from ..database import session_scope
from ..models import Repository, Scan
from .policy import discover_policy
from .scanner import ScanRequest, run_scan
from .store import apply_outcome, audit, dashboard_suppressions

_INFO = 20
_WARN = 30


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanJobManager:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._executor = ThreadPoolExecutor(max_workers=settings.max_concurrent_scans, thread_name_prefix="ss-scan")
        self._cancel: dict[str, threading.Event] = {}
        self._lock = threading.Lock()
        self._closed = False

    def submit(self, scan_id: str) -> None:
        event = threading.Event()
        with self._lock:
            if self._closed:
                raise SecretSentinelError(ErrorCode.INVALID_STATE)
            self._cancel[scan_id] = event
        self._executor.submit(self._run, scan_id, event)

    def cancel(self, scan_id: str) -> bool:
        with self._lock:
            event = self._cancel.get(scan_id)
        if event is None:
            return False
        event.set()
        return True

    def is_active(self, scan_id: str) -> bool:
        with self._lock:
            return scan_id in self._cancel

    def shutdown(self) -> None:
        with self._lock:
            self._closed = True
            events = list(self._cancel.values())
        for e in events:
            e.set()
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _fail(self, scan_id: str, code: ErrorCode) -> None:
        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return
            scan.status = "cancelled" if code == ErrorCode.SCAN_CANCELLED else "failed"
            scan.policy_result = "not_evaluated"
            scan.error_code = code.value
            scan.finished_at = _utcnow()
            audit(session, "system", "scan.finished", "scan", scan.id, status=scan.status, error_code=code.value)

    def _run(self, scan_id: str, cancel_event: threading.Event) -> None:
        try:
            with session_scope() as session:
                scan = session.get(Scan, scan_id)
                if scan is None or scan.status != "queued":
                    return
                if cancel_event.is_set():
                    raise SecretSentinelError(ErrorCode.SCAN_CANCELLED)
                repo = session.get(Repository, scan.repository_id)
                scan.status = "running"
                scan.started_at = _utcnow()
                raw_path = repo.canonical_local_path
                repo_id = repo.id
                mode, since_ref, fail_on = scan.mode, scan.since_ref, scan.fail_on
                extra = dashboard_suppressions(session, repo_id)
            target = canonicalize_existing_dir(raw_path)
            ensure_within_allowed_roots(target, self.settings.scan_root_allowlist)
            policy = discover_policy(target)
            effective_fail_on = fail_on or policy.fail_on or self.settings.default_fail_on
            outcome = run_scan(
                ScanRequest(
                    target=target,
                    mode=mode,
                    since_ref=since_ref,
                    fail_on=effective_fail_on,
                    policy=policy,
                    extra_suppressions=extra,
                    timeout_seconds=self.settings.scanner_timeout_seconds,
                    max_file_mb=self.settings.max_scan_file_mb,
                    cancel_event=cancel_event,
                ),
                self.settings,
            )
            with session_scope() as session:
                scan = session.get(Scan, scan_id)
                if scan is None:
                    return
                apply_outcome(session, scan, outcome)
                audit(session, "system", "scan.finished", "scan", scan.id, status=scan.status, error_code=scan.error_code)
        except SecretSentinelError as exc:
            self._fail(scan_id, exc.code)
        except Exception:  # noqa: BLE001 - fail closed, never leak details
            log_event(_WARN, "scan.job_error", scan_id=scan_id, error_code=ErrorCode.INTERNAL_ERROR.value)
            self._fail(scan_id, ErrorCode.INTERNAL_ERROR)
        finally:
            with self._lock:
                self._cancel.pop(scan_id, None)
