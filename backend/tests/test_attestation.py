"""P2 attestation canonicalisation, signing and verification (T15, T16)."""

import copy
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

pytest.importorskip("eth_account")

from eth_account import Account  # noqa: E402

from secretsentinel.core.errors import SecretSentinelError  # noqa: E402
from secretsentinel.services import attestation as att  # noqa: E402

SEPOLIA = 11155111


def _scan(**kw):
    base = dict(
        id="4ea88069-a486-49d7-b6cd-47d690097967", status="completed", secretsentinel_version="1.0.0",
        scanner_name="gitleaks", scanner_version="8.30.1", ruleset_digest="sha256:" + "a" * 64,
        policy_digest="sha256:" + "b" * 64, mode="both", scope="working-tree+full-history", policy_result="pass",
        fail_on="high", blocking_findings=0, total_findings=2, commit_sha="0123456789abcdef0123456789abcdef01234567",
        finished_at=datetime(2026, 11, 10, 10, 0, tzinfo=timezone.utc),
    )
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.fixture
def signer():
    acct = Account.create()
    return acct.key.hex(), acct.address


def _signed(signer, **kw):
    key, address = signer
    payload, disclosure = att.build_payload(_scan(**kw), SEPOLIA)
    digest = att.digest_of(payload)
    sig, addr = att.sign_digest(digest, key)
    assert addr == address
    return payload, digest, sig, disclosure


def test_payload_is_non_sensitive_and_canonical(signer):
    payload, digest, _sig, disclosure = _signed(signer)
    assert set(payload) <= att.PAYLOAD_KEYS
    assert "commit_sha" not in payload and payload["commit_commitment"].startswith("sha256:")
    assert disclosure["commit_sha"] and disclosure["salt"]
    shuffled = dict(reversed(list(payload.items())))
    assert att.canonical_json(shuffled) == att.canonical_json(payload)
    assert digest.startswith("0x") and len(digest) == 66


def test_only_completed_scans_attestable():
    with pytest.raises(SecretSentinelError):
        att.build_payload(_scan(status="failed"), SEPOLIA)


def test_floats_rejected():
    with pytest.raises(SecretSentinelError):
        att.canonical_json({"x": 1.5})


def test_valid_attestation_verifies(signer):
    payload, digest, sig, _ = _signed(signer)
    r = att.verify(payload, sig, signer[1], (signer[1],), SEPOLIA, expected_digest=digest)
    assert r.verified and r.label == "Attestation verified"
    assert "does NOT prove the code is secure" in r.as_dict()["disclaimer"]


def test_T15_modified_payload_fails(signer):
    payload, digest, sig, _ = _signed(signer)
    tampered = copy.deepcopy(payload)
    tampered["policy_result"] = "pass" if payload["policy_result"] == "fail" else "fail"
    tampered["blocking_findings_count"] = 5
    r = att.verify(tampered, sig, signer[1], (signer[1],), SEPOLIA, expected_digest=digest)
    assert not r.verified
    failed = {c.name for c in r.checks if not c.ok}
    assert {"digest-match", "signature"} <= failed


def test_T16_untrusted_signer_fails(signer):
    payload, digest, sig, _ = _signed(signer)
    other = Account.create().address
    r = att.verify(payload, sig, signer[1], (other,), SEPOLIA, expected_digest=digest)
    assert not r.verified and any(c.name == "trusted-signer" and not c.ok for c in r.checks)
    r = att.verify(payload, sig, signer[1], (), SEPOLIA)
    assert not r.verified  # no trust anchor configured -> never "verified"


def test_T16_wrong_chain_fails(signer):
    payload, digest, sig, _ = _signed(signer)
    r = att.verify(payload, sig, signer[1], (signer[1],), 1, expected_digest=digest)
    assert not r.verified and any(c.name == "chain-binding" and not c.ok for c in r.checks)


def test_onchain_checks(signer):
    payload, digest, sig, _ = _signed(signer)
    good = lambda d: (SEPOLIA, "0x" + "c" * 40, signer[1])  # noqa: E731
    assert att.verify(payload, sig, signer[1], (signer[1],), SEPOLIA, onchain_lookup=good).verified
    wrong_chain = lambda d: (1, "0x" + "c" * 40, signer[1])  # noqa: E731
    assert not att.verify(payload, sig, signer[1], (signer[1],), SEPOLIA, onchain_lookup=wrong_chain).verified
    missing = lambda d: (SEPOLIA, "0x" + "c" * 40, None)  # noqa: E731
    assert not att.verify(payload, sig, signer[1], (signer[1],), SEPOLIA, onchain_lookup=missing).verified
    other_pub = lambda d: (SEPOLIA, "0x" + "c" * 40, Account.create().address)  # noqa: E731
    assert not att.verify(payload, sig, signer[1], (signer[1],), SEPOLIA, onchain_lookup=other_pub).verified


def test_extra_payload_fields_fail_schema(signer):
    payload, _digest, _sig, _ = _signed(signer)
    payload["repository_url"] = "https://example.invalid/private"
    key = signer[0]
    sig2, _ = att.sign_digest(att.digest_of(payload), key)
    r = att.verify(payload, sig2, signer[1], (signer[1],), SEPOLIA)
    assert not r.verified and any(c.name == "payload-schema" and not c.ok for c in r.checks)


def test_signer_key_reference_rules(monkeypatch, signer):
    with pytest.raises(SecretSentinelError):
        att.load_signer_key(signer[0])  # raw keys refused
    with pytest.raises(SecretSentinelError):
        att.load_signer_key("env:NOT_SET_VAR")
    monkeypatch.setenv("SS_TEST_SIGNER", signer[0])
    assert att.load_signer_key("env:SS_TEST_SIGNER") == signer[0]
    with pytest.raises(SecretSentinelError):
        att.load_signer_key("http://somewhere")


def test_chain_selector_encoding():
    from secretsentinel.services.chain import selector

    # Well-known ERC-20 selector proves the keccak/selector helper is correct.
    assert selector("transfer(address,uint256)") == "0xa9059cbb"
