"""FastAPI application factory.

Security defaults (PRD 8.2, 11, 16):

* Binds to 127.0.0.1. Refuses a non-loopback bind unless ALLOW_REMOTE=true
  AND an API_TOKEN is configured.
* TrustedHost check (defends the loopback API against DNS rebinding).
* CORS limited to the local dashboard origins; Origin checked on writes.
* Mutating requests must be application/json (blocks simple cross-site forms).
* Optional bearer-token auth and rate limiting for remote mode.
* Errors use controlled codes; validation errors never echo request input;
  unhandled exceptions return a generic INTERNAL_ERROR.
* No raw scanner output can be returned: routes only serialize sanitized
  ORM fields through explicit response models.
"""

from __future__ import annotations

import hmac
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .core.config import Settings, get_settings, set_settings
from .core.errors import ErrorCode, SecretSentinelError
from .core.log import configure_logging, log_event
from .database import init_engine, mark_interrupted_scans, prune_old_scans, session_scope
from .paths import find_frontend_dist
from .services.jobs import ScanJobManager

API_PREFIX = "/api/v1"

STATUS_FOR = {
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.FEATURE_DISABLED: 404,
    ErrorCode.VALIDATION_ERROR: 422,
    ErrorCode.PATH_NOT_FOUND: 422,
    ErrorCode.INVALID_GIT_REF: 422,
    ErrorCode.UNSUPPORTED_REPO: 422,
    ErrorCode.REPO_TOO_LARGE: 422,
    ErrorCode.INVALID_POLICY: 422,
    ErrorCode.PATH_NOT_ALLOWED: 403,
    ErrorCode.FORBIDDEN_ORIGIN: 403,
    ErrorCode.UNAUTHORIZED: 401,
    ErrorCode.SCAN_ALREADY_RUNNING: 409,
    ErrorCode.INVALID_STATE: 409,
    ErrorCode.UNSUPPORTED_MEDIA_TYPE: 415,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.SCANNER_NOT_FOUND: 503,
    ErrorCode.GIT_NOT_FOUND: 503,
    ErrorCode.ATTESTATION_ERROR: 422,
}

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
FRONTEND_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)


def error_response(code: ErrorCode, message: str | None = None, status: int | None = None, **extra) -> JSONResponse:
    from .core.errors import SAFE_MESSAGES

    body = {"error": {"code": code.value, "message": message or SAFE_MESSAGES[code], **extra}}
    return JSONResponse(body, status_code=status or STATUS_FOR.get(code, 500), headers={"Cache-Control": "no-store"})


def validate_startup(settings: Settings) -> None:
    if not settings.is_loopback and not (settings.allow_remote and settings.api_token):
        raise SecretSentinelError(
            ErrorCode.UNAUTHORIZED,
            "Refusing to bind to a non-loopback address without ALLOW_REMOTE=true and API_TOKEN. "
            "Remote use also requires HTTPS via a reverse proxy.",
        )


class _RateLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self.hits: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= self.per_minute:
                return False
            q.append(now)
            return True


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    set_settings(settings)
    configure_logging(settings.log_level)
    init_engine(settings.db_url)
    with session_scope() as session:
        mark_interrupted_scans(session)
        prune_old_scans(session, settings.scan_retention_days)
    jobs = ScanJobManager(settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        jobs.shutdown()

    dev = settings.app_env == "development"
    app = FastAPI(
        title="SecretSentinel API",
        version=__version__,
        docs_url="/api/docs" if dev else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if dev else None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.jobs = jobs
    limiter = _RateLimiter(settings.rate_limit_per_minute)
    remote_mode = bool(settings.api_token) or not settings.is_loopback
    allowed_origins = set(settings.cors_origins)

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        path = request.url.path
        is_api = path.startswith("/api/")
        method = request.method.upper()
        if is_api and method in ("POST", "PUT", "PATCH", "DELETE"):
            origin = request.headers.get("origin")
            if origin:
                host = request.headers.get("host", "")
                same_origin = origin in (f"http://{host}", f"https://{host}")
                if origin not in allowed_origins and not same_origin:
                    return error_response(ErrorCode.FORBIDDEN_ORIGIN)
            if method in ("POST", "PUT", "PATCH"):
                ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
                has_body = request.headers.get("content-length", "0") not in ("", "0") or "transfer-encoding" in request.headers
                if (has_body or ctype) and ctype != "application/json":
                    return error_response(ErrorCode.UNSUPPORTED_MEDIA_TYPE)
        if is_api and remote_mode:
            client = request.client.host if request.client else "unknown"
            if not limiter.allow(client):
                return error_response(ErrorCode.RATE_LIMITED)
        if (
            is_api
            and settings.api_token
            and path not in (f"{API_PREFIX}/health",)
            and not path.startswith(f"{API_PREFIX}/ingest/")
            and method != "OPTIONS"
        ):
            header = request.headers.get("authorization", "")
            supplied = header[7:] if header.lower().startswith("bearer ") else ""
            if not supplied or not hmac.compare_digest(supplied.encode(), settings.api_token.encode()):
                return error_response(ErrorCode.UNAUTHORIZED)
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if is_api:
            response.headers["Cache-Control"] = "no-store"
        else:
            response.headers.setdefault("Content-Security-Policy", FRONTEND_CSP)
        return response

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "Authorization"],
        max_age=600,
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.trusted_hosts))

    @app.exception_handler(SecretSentinelError)
    async def _ss_error(_request: Request, exc: SecretSentinelError):
        return error_response(exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_request: Request, exc: RequestValidationError):
        # Never echo submitted values back (they could contain anything).
        fields = [
            {"loc": [str(p) for p in e.get("loc", ())][:6], "msg": str(e.get("msg", ""))[:200]}
            for e in exc.errors()[:20]
        ]
        return error_response(ErrorCode.VALIDATION_ERROR, fields=fields)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_request: Request, exc: StarletteHTTPException):
        if exc.status_code == 404:
            return error_response(ErrorCode.NOT_FOUND)
        if exc.status_code == 405:
            return error_response(ErrorCode.VALIDATION_ERROR, "Method not allowed.", status=405)
        return error_response(ErrorCode.INTERNAL_ERROR, status=exc.status_code)

    @app.exception_handler(Exception)
    async def _unhandled(_request: Request, _exc: Exception):
        log_event(40, "api.unhandled_error", error_code=ErrorCode.INTERNAL_ERROR.value)
        return error_response(ErrorCode.INTERNAL_ERROR)

    from .api import routes_findings, routes_ingest, routes_metrics, routes_repositories, routes_scans
    from .api.routes_attestations import router as attestations_router

    @app.get(f"{API_PREFIX}/health", tags=["health"])
    def health():
        return {"status": "ok"}

    for r in (
        routes_repositories.router,
        routes_scans.router,
        routes_findings.router,
        routes_metrics.router,
        routes_ingest.router,
        attestations_router,
    ):
        app.include_router(r, prefix=API_PREFIX)

    dist = find_frontend_dist()
    if dist is not None:
        _mount_frontend(app, dist)
    return app


def _mount_frontend(app: FastAPI, dist: Path) -> None:
    """Serve the built React app (single-page app fallback to index.html)."""
    dist = dist.resolve()
    index = dist / "index.html"

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        if full_path.startswith("api/"):
            raise StarletteHTTPException(status_code=404)
        candidate = (dist / full_path).resolve()
        if full_path and candidate.is_file() and candidate.is_relative_to(dist):
            return FileResponse(candidate)
        return FileResponse(index)
