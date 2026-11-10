"""P2 (optional) attestation endpoints. Return FEATURE_DISABLED unless ENABLE_BLOCKCHAIN=true."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import Settings
from ..core.errors import ErrorCode, SecretSentinelError
from ..models import Attestation, Scan
from ..schemas import AttestationOut, AttestationVerifyRequest, AttestationVerifyResult
from ..services import attestation as att
from ..services.store import audit
from .deps import _aware, get_db, get_or_404, get_settings

router = APIRouter(tags=["attestations"])


def require_blockchain(settings: Settings = Depends(get_settings)) -> Settings:
    if not settings.enable_blockchain:
        raise SecretSentinelError(ErrorCode.FEATURE_DISABLED)
    return settings


def _out(a: Attestation) -> AttestationOut:
    payload = json.loads(a.payload_json)
    return AttestationOut(
        scan_id=a.scan_id,
        payload=payload,
        canonical_payload=att.canonical_json(payload),
        attestation_digest=a.attestation_digest,
        signature=a.signature,
        signer_address=a.signer_address,
        chain_id=a.chain_id,
        contract_address=a.contract_address,
        transaction_hash=a.transaction_hash,
        published_at=_aware(a.published_at),
    )


@router.post("/attestations/verify", response_model=AttestationVerifyResult)
def verify_attestation(body: AttestationVerifyRequest, settings: Settings = Depends(require_blockchain)):
    lookup = None
    if body.check_onchain:
        if not (settings.sepolia_rpc_url and settings.attestation_contract_address):
            raise SecretSentinelError(ErrorCode.FEATURE_DISABLED, "Configure SEPOLIA_RPC_URL and ATTESTATION_CONTRACT_ADDRESS.")
        from ..services.chain import make_lookup

        lookup = make_lookup(settings.sepolia_rpc_url, settings.attestation_contract_address)
    result = att.verify(
        body.payload,
        body.signature,
        body.signer_address,
        settings.trusted_attestation_signers,
        settings.attestation_chain_id,
        onchain_lookup=lookup,
    )
    return result.as_dict()


@router.get("/attestations/{scan_id}", response_model=AttestationOut)
def get_attestation(scan_id: str, session: Session = Depends(get_db, scope="function"), _s: Settings = Depends(require_blockchain)):
    a = session.scalar(select(Attestation).where(Attestation.scan_id == scan_id))
    if a is None:
        raise SecretSentinelError(ErrorCode.NOT_FOUND)
    return _out(a)


@router.post("/attestations/{scan_id}", response_model=AttestationOut, status_code=status.HTTP_201_CREATED)
def create_attestation(scan_id: str, session: Session = Depends(get_db, scope="function"), settings: Settings = Depends(require_blockchain)):
    scan = get_or_404(session, Scan, scan_id)
    if session.scalar(select(Attestation).where(Attestation.scan_id == scan_id)) is not None:
        raise SecretSentinelError(ErrorCode.INVALID_STATE, "Scan already attested.")
    payload, _disclosure = att.build_payload(scan, settings.attestation_chain_id, private_commit=True)
    digest = att.digest_of(payload)
    key = att.load_signer_key(settings.attestation_signer_key_reference)
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
    audit(session, "local-user", "attestation.created", "scan", scan.id, digest=digest, signer=signer)
    session.flush()
    return _out(a)


_ = datetime, timezone
