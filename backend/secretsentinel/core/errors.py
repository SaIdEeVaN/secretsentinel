"""Controlled error codes.

Every error that can reach a user, an API client, a CI log or the database is
expressed as one of these codes plus a FIXED, pre-written message. Raw
exception text, subprocess stdout/stderr and file contents are never used as
error messages, because they may contain candidate secrets.
"""

from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    # Scanner / pipeline
    SCANNER_NOT_FOUND = "SCANNER_NOT_FOUND"
    SCANNER_ERROR = "SCANNER_ERROR"
    SCAN_TIMEOUT = "SCAN_TIMEOUT"
    SCAN_CANCELLED = "SCAN_CANCELLED"
    SCAN_INTERRUPTED = "SCAN_INTERRUPTED"
    UNSUPPORTED_REPO = "UNSUPPORTED_REPO"
    INVALID_CONFIG = "INVALID_CONFIG"
    INVALID_POLICY = "INVALID_POLICY"
    REPORT_PARSE_FAILED = "REPORT_PARSE_FAILED"
    SANITIZATION_FAILED = "SANITIZATION_FAILED"
    GIT_NOT_FOUND = "GIT_NOT_FOUND"
    INVALID_GIT_REF = "INVALID_GIT_REF"
    # Paths
    PATH_NOT_FOUND = "PATH_NOT_FOUND"
    PATH_NOT_ALLOWED = "PATH_NOT_ALLOWED"
    REPO_TOO_LARGE = "REPO_TOO_LARGE"
    # API
    NOT_FOUND = "NOT_FOUND"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    SCAN_ALREADY_RUNNING = "SCAN_ALREADY_RUNNING"
    INVALID_STATE = "INVALID_STATE"
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN_ORIGIN = "FORBIDDEN_ORIGIN"
    UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"
    RATE_LIMITED = "RATE_LIMITED"
    FEATURE_DISABLED = "FEATURE_DISABLED"
    ATTESTATION_ERROR = "ATTESTATION_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


SAFE_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.SCANNER_NOT_FOUND: "Gitleaks executable was not found. Install it and/or set GITLEAKS_PATH.",
    ErrorCode.SCANNER_ERROR: "The scanner exited with an error; security status is unknown.",
    ErrorCode.SCAN_TIMEOUT: "The scan exceeded its time limit; security status is unknown.",
    ErrorCode.SCAN_CANCELLED: "The scan was cancelled before completion.",
    ErrorCode.SCAN_INTERRUPTED: "The scan was interrupted (for example by a server restart).",
    ErrorCode.UNSUPPORTED_REPO: "The target is not a Git repository, so Git history cannot be scanned.",
    ErrorCode.INVALID_CONFIG: "The scanner ruleset or generated configuration is invalid.",
    ErrorCode.INVALID_POLICY: "The SecretSentinel policy file is invalid.",
    ErrorCode.REPORT_PARSE_FAILED: "The scanner report could not be parsed; security status is unknown.",
    ErrorCode.SANITIZATION_FAILED: "Scanner output failed sanitization and was discarded.",
    ErrorCode.GIT_NOT_FOUND: "Git executable was not found on PATH.",
    ErrorCode.INVALID_GIT_REF: "The supplied Git reference is invalid or does not resolve to a commit.",
    ErrorCode.PATH_NOT_FOUND: "The path does not exist or is not a directory.",
    ErrorCode.PATH_NOT_ALLOWED: "The path is outside the configured scan root allowlist.",
    ErrorCode.REPO_TOO_LARGE: "The target exceeds the configured maximum repository size.",
    ErrorCode.NOT_FOUND: "The requested resource was not found.",
    ErrorCode.VALIDATION_ERROR: "The request was invalid.",
    ErrorCode.SCAN_ALREADY_RUNNING: "A scan for this repository is already queued or running.",
    ErrorCode.INVALID_STATE: "The operation is not valid in the resource's current state.",
    ErrorCode.UNAUTHORIZED: "Authentication is required.",
    ErrorCode.FORBIDDEN_ORIGIN: "Request origin is not allowed.",
    ErrorCode.UNSUPPORTED_MEDIA_TYPE: "Request body must be application/json.",
    ErrorCode.RATE_LIMITED: "Too many requests; slow down.",
    ErrorCode.FEATURE_DISABLED: "This optional feature is disabled.",
    ErrorCode.ATTESTATION_ERROR: "Attestation could not be created or verified.",
    ErrorCode.INTERNAL_ERROR: "An internal error occurred.",
}


class SecretSentinelError(Exception):
    """Exception carrying a controlled error code.

    ``detail`` must only ever be a constant, developer-written string (never
    derived from scanned content or subprocess output).
    """

    def __init__(self, code: ErrorCode, detail: str | None = None):
        self.code = code
        self.detail = detail
        super().__init__(code.value)

    @property
    def message(self) -> str:
        base = SAFE_MESSAGES[self.code]
        return f"{base} {self.detail}" if self.detail else base


def safe_message(code: ErrorCode | str | None) -> str | None:
    if code is None:
        return None
    try:
        return SAFE_MESSAGES[ErrorCode(code)]
    except ValueError:
        return SAFE_MESSAGES[ErrorCode.INTERNAL_ERROR]
