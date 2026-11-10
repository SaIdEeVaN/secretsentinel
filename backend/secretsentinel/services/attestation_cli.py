"""CLI handlers for ``secretsentinel attest ...`` (optional P2)."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from ..core.config import Settings
from ..core.errors import ErrorCode, SecretSentinelError
from . import attestation as att

BUNDLE_SCHEMA = "secretsentinel-attestation-bundle/v1"


def _session(settings: Settings):
    from ..database import init_engine, session_scope

    init_engine(settings.db_url)
    return session_scope()


def _bundle(a, disclosure: dict | None = None) -> dict:
    payload = json.loads(a.payload_json)
    bundle = {
        "schema": BUNDLE_SCHEMA,
        "payload": payload,
        "attestation_digest": a.attestation_digest,
        "signature": a.signature,
        "signer_address": a.signer_address,
        "chain_id": a.chain_id,
        "contract_address": a.contract_address,
        "transaction_hash": a.transaction_hash,
        "disclaimer": att.DISCLAIMER,
    }
    if disclosure:
        bundle["private_disclosure"] = {
            **disclosure,
            "note": "Share only with authorized verifiers. Not part of the signed digest.",
        }
    return bundle


def run(args, settings: Settings) -> int:
    if not settings.enable_blockchain:
        print("secretsentinel: attestations are disabled (set ENABLE_BLOCKCHAIN=true)", file=sys.stderr)
        return 2
    try:
        if args.attest_cmd == "create":
            return _create(args, settings)
        if args.attest_cmd == "publish":
            return _publish(args, settings)
        if args.attest_cmd == "verify":
            return _verify(args, settings)
    except SecretSentinelError as exc:
        print(f"secretsentinel: [{exc.code.value}] {exc.message}", file=sys.stderr)
        return 3
    return 2


def _create(args, settings: Settings) -> int:
    from sqlalchemy import select

    from ..models import Attestation, Scan

    with _session(settings) as session:
        scan = session.get(Scan, args.scan_id)
        if scan is None:
            raise SecretSentinelError(ErrorCode.NOT_FOUND)
        if session.scalar(select(Attestation).where(Attestation.scan_id == scan.id)):
            raise SecretSentinelError(ErrorCode.INVALID_STATE, "Scan already attested.")
        payload, disclosure = att.build_payload(scan, settings.attestation_chain_id, private_commit=True)
        digest = att.digest_of(payload)
        key = att.load_signer_key(settings.attestation_signer_key_reference, interactive=True)
        signature, signer = att.sign_digest(digest, key)
        del key
        a = Attestation(
            scan_id=scan.id,
            payload_json=att.canonical_json(payload),
            attestation_digest=digest,
            signature=signature,
            signer_address=signer,
            chain_id=settings.attestation_chain_id,
            contract_address=settings.attestation_contract_address,
        )
        session.add(a)
        session.flush()
        bundle = _bundle(a, disclosure)
    text = json.dumps(bundle, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Attestation {digest} signed by {signer}; bundle written to {args.output}")
    else:
        sys.stdout.write(text)
    return 0


def _publish(args, settings: Settings) -> int:
    from sqlalchemy import select

    from ..models import Attestation
    from .chain import register

    if not (settings.sepolia_rpc_url and settings.attestation_contract_address):
        raise SecretSentinelError(ErrorCode.FEATURE_DISABLED, "Configure SEPOLIA_RPC_URL and ATTESTATION_CONTRACT_ADDRESS.")
    with _session(settings) as session:
        a = session.scalar(select(Attestation).where(Attestation.scan_id == args.scan_id))
        if a is None:
            raise SecretSentinelError(ErrorCode.NOT_FOUND, "Create the attestation first.")
        key = att.load_signer_key(settings.attestation_signer_key_reference, interactive=True)
        tx = register(settings.sepolia_rpc_url, settings.attestation_contract_address, a.attestation_digest, key,
                      settings.attestation_chain_id)
        del key
        a.transaction_hash = tx
        a.contract_address = settings.attestation_contract_address
        a.published_at = datetime.now(timezone.utc)
    print(f"Registered digest on chain {settings.attestation_chain_id}: tx {tx}")
    return 0


def _verify(args, settings: Settings) -> int:
    bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    if bundle.get("schema") != BUNDLE_SCHEMA:
        raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "Unsupported bundle schema.")
    lookup = None
    if args.onchain:
        from .chain import make_lookup

        contract = settings.attestation_contract_address
        if not (settings.sepolia_rpc_url and contract):
            raise SecretSentinelError(ErrorCode.FEATURE_DISABLED, "Configure SEPOLIA_RPC_URL and ATTESTATION_CONTRACT_ADDRESS.")
        lookup = make_lookup(settings.sepolia_rpc_url, contract)
    result = att.verify(
        bundle["payload"], bundle["signature"], bundle["signer_address"], settings.trusted_attestation_signers,
        settings.attestation_chain_id, expected_digest=bundle.get("attestation_digest"), onchain_lookup=lookup,
    )
    for c in result.checks:
        print(f"  [{'ok' if c.ok else 'FAIL'}] {c.name}: {c.detail}")
    print(result.label)
    print(att.DISCLAIMER)
    return 0 if result.verified else 1
