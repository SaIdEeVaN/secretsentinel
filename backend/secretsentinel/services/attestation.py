"""P2 (optional): signed, non-sensitive scan attestations.

Trust model (PRD 15.4):

* The attestation payload holds ONLY scan-level metadata: scan id, commit
  (or a salted commitment to it), tool/ruleset/policy digests, status,
  policy result and counts. Never secrets, findings, paths, repository names
  or personal data.
* ``digest = SHA-256(canonical_json(payload))``; the publisher signs the
  digest (EIP-191 ``personal_sign``) and only the digest goes on-chain.
* Verification recomputes the digest, recovers the signer, requires the
  signer to be explicitly trusted, and optionally checks the Sepolia
  registry for the same digest/publisher on the expected chain/contract.
* A verified attestation proves WHO attested to a scan result and that it was
  not modified. It does NOT prove the code is secure.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass, field
from datetime import timezone
from typing import Any

from ..core.errors import ErrorCode, SecretSentinelError

SCHEMA_VERSION = "1"
DISCLAIMER = (
    "Verification shows who attested to this scan result and that the attestation was not modified. "
    "It does NOT prove the code is secure, that the scan covered everything, or that no secrets exist."
)
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEX_KEY_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
PAYLOAD_KEYS = {
    "schema_version", "scan_id", "commit_sha", "commit_commitment", "scanner", "scanner_version",
    "detector", "detector_version", "ruleset_sha256", "policy_sha256", "mode", "scope", "status",
    "policy_result", "fail_on", "blocking_findings_count", "total_findings_count", "completed_at", "chain_id",
}


def _require_eth():
    try:
        from eth_account import Account
        from eth_account.messages import encode_defunct
    except ImportError:  # pragma: no cover - optional dependency
        raise SecretSentinelError(
            ErrorCode.FEATURE_DISABLED, "Install the optional dependency: pip install -e 'backend[blockchain]'."
        ) from None
    return Account, encode_defunct


def canonical_json(payload: dict) -> str:
    """Deterministic JSON: sorted keys, no whitespace, ASCII, no floats."""

    def check(value: Any) -> None:
        if isinstance(value, float):
            raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "Floats are not allowed in attestations.")
        if isinstance(value, dict):
            for k, v in value.items():
                if not isinstance(k, str):
                    raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR)
                check(v)
        elif isinstance(value, list):
            for v in value:
                check(v)
        elif not isinstance(value, (str, int, bool, type(None))):
            raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR)

    check(payload)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest_of(payload: dict) -> str:
    return "0x" + hashlib.sha256(canonical_json(payload).encode("ascii")).hexdigest()


def _strip(d: str | None) -> str | None:
    return d.split(":", 1)[1] if d and ":" in d else d


def build_payload(scan, chain_id: int, private_commit: bool = True) -> tuple[dict, dict]:
    """Build the attestation payload for a completed scan row.

    Returns ``(payload, private_disclosure)``. With ``private_commit`` the
    commit SHA is replaced by ``sha256(salt || sha)`` and the salt is kept in
    the private disclosure, to be shared only with authorized verifiers.
    """
    if scan.status != "completed":
        raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "Only completed scans can be attested.")
    finished = scan.finished_at
    if finished is not None and finished.tzinfo is None:
        finished = finished.replace(tzinfo=timezone.utc)
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "scan_id": scan.id,
        "scanner": "SecretSentinel",
        "scanner_version": scan.secretsentinel_version,
        "detector": scan.scanner_name,
        "detector_version": scan.scanner_version,
        "ruleset_sha256": _strip(scan.ruleset_digest),
        "policy_sha256": _strip(scan.policy_digest),
        "mode": scan.mode,
        "scope": scan.scope,
        "status": scan.status,
        "policy_result": scan.policy_result,
        "fail_on": scan.fail_on,
        "blocking_findings_count": int(scan.blocking_findings),
        "total_findings_count": int(scan.total_findings),
        "completed_at": finished.strftime("%Y-%m-%dT%H:%M:%SZ") if finished else None,
        "chain_id": int(chain_id),
    }
    disclosure: dict[str, Any] = {}
    if scan.commit_sha:
        if private_commit:
            salt = secrets.token_hex(16)
            payload["commit_commitment"] = "sha256:" + hashlib.sha256(bytes.fromhex(salt) + scan.commit_sha.encode()).hexdigest()
            disclosure = {"commit_sha": scan.commit_sha, "salt": salt}
        else:
            payload["commit_sha"] = scan.commit_sha
    return payload, disclosure


def load_signer_key(reference: str | None, interactive: bool = False) -> str:
    """Resolve ATTESTATION_SIGNER_KEY_REFERENCE without ever logging the key.

    Supported forms: ``env:VARNAME`` and ``keystore:/path/to/keystore.json``
    (password from ATTESTATION_KEYSTORE_PASSWORD or an interactive prompt).
    A raw key in the reference itself is rejected.
    """
    if not reference:
        raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "ATTESTATION_SIGNER_KEY_REFERENCE is not set.")
    if _HEX_KEY_RE.match(reference.strip()):
        raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "Use an env: or keystore: reference, not a raw key.")
    kind, _, value = reference.partition(":")
    if kind == "env":
        key = os.environ.get(value)
        if not key:
            raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "Referenced key variable is empty.")
        return key
    if kind == "keystore":
        Account, _ = _require_eth()
        password = os.environ.get("ATTESTATION_KEYSTORE_PASSWORD")
        if password is None and interactive:
            import getpass

            password = getpass.getpass("Keystore password: ")
        if password is None:
            raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "Keystore password unavailable.")
        try:
            with open(value, encoding="utf-8") as fh:
                return Account.decrypt(json.load(fh), password).hex()
        except Exception:  # noqa: BLE001 - never echo keystore errors
            raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "Could not decrypt keystore.") from None
    raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "Unsupported key reference type.")


def sign_digest(digest_hex: str, private_key: str) -> tuple[str, str]:
    Account, encode_defunct = _require_eth()
    digest = bytes.fromhex(digest_hex[2:])
    try:
        acct = Account.from_key(private_key)
        signed = acct.sign_message(encode_defunct(primitive=digest))
    except Exception:  # noqa: BLE001
        raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "Signing failed.") from None
    sig = signed.signature.hex()
    return ("0x" + sig) if not sig.startswith("0x") else sig, acct.address


def recover_signer(digest_hex: str, signature: str) -> str | None:
    Account, encode_defunct = _require_eth()
    try:
        return Account.recover_message(encode_defunct(primitive=bytes.fromhex(digest_hex[2:])), signature=signature)
    except Exception:  # noqa: BLE001
        return None


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


@dataclass
class VerificationResult:
    verified: bool
    digest: str | None
    recovered_signer: str | None
    checks: list[Check] = field(default_factory=list)

    @property
    def label(self) -> str:
        return "Attestation verified" if self.verified else "Attestation NOT verified"

    def as_dict(self) -> dict:
        return {
            "verified": self.verified,
            "label": self.label,
            "attestation_digest": self.digest,
            "recovered_signer": self.recovered_signer,
            "checks": [c.__dict__ for c in self.checks],
            "disclaimer": DISCLAIMER,
        }


def verify(
    payload: dict,
    signature: str,
    claimed_signer: str,
    trusted_signers: tuple[str, ...],
    expected_chain_id: int,
    expected_digest: str | None = None,
    onchain_lookup=None,
) -> VerificationResult:
    """Verify an attestation. ``onchain_lookup(digest) -> (chain_id, contract, publisher|None)``."""
    checks: list[Check] = []
    digest = None
    recovered = None
    unknown = set(payload) - PAYLOAD_KEYS
    checks.append(Check("payload-schema", not unknown and payload.get("schema_version") == SCHEMA_VERSION,
                        "Only scan-level, non-sensitive fields are present" if not unknown else "Unexpected fields present"))
    try:
        digest = digest_of(payload)
        checks.append(Check("canonical-digest", True, digest))
    except SecretSentinelError:
        checks.append(Check("canonical-digest", False, "Payload cannot be canonicalized"))
    if expected_digest is not None:
        checks.append(Check("digest-match", digest == expected_digest.lower(), "Recomputed digest matches the published digest"
                            if digest == expected_digest.lower() else "Payload was modified after signing"))
    if digest:
        recovered = recover_signer(digest, signature)
    sig_ok = bool(recovered) and bool(_ADDRESS_RE.match(claimed_signer or "")) and recovered.lower() == claimed_signer.lower()
    checks.append(Check("signature", sig_ok, "Signature recovers to the claimed signer" if sig_ok else "Signature does not match payload/signer"))
    trusted = {t.lower() for t in trusted_signers}
    signer_trusted = bool(recovered) and recovered.lower() in trusted
    checks.append(Check(
        "trusted-signer", signer_trusted,
        "Signer is in TRUSTED_ATTESTATION_SIGNERS" if signer_trusted else
        ("No trusted signers configured" if not trusted else "Signer is not trusted"),
    ))
    chain_ok = payload.get("chain_id") == expected_chain_id
    checks.append(Check("chain-binding", chain_ok, f"Payload bound to chain {payload.get('chain_id')}, expected {expected_chain_id}"))
    if onchain_lookup is not None and digest:
        try:
            chain_id, contract, publisher = onchain_lookup(digest)
            checks.append(Check("onchain-chain", chain_id == expected_chain_id, f"RPC chain id {chain_id}"))
            registered = publisher is not None
            checks.append(Check("onchain-registered", registered, f"Digest registered in {contract}" if registered else "Digest not found in registry"))
            pub_ok = registered and recovered is not None and publisher.lower() == recovered.lower()
            checks.append(Check("onchain-publisher", pub_ok, "On-chain publisher matches signer" if pub_ok else "On-chain publisher does not match signer"))
        except SecretSentinelError as exc:
            checks.append(Check("onchain", False, exc.message))
    verified = all(c.ok for c in checks)
    return VerificationResult(verified=verified, digest=digest, recovered_signer=recovered, checks=checks)
