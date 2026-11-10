"""P2 interop: Python attestation client <-> ScanRegistry on a LOCAL dev chain.

Runs only when a local JSON-RPC node with a deployed registry is provided
(see .github/workflows/contracts-tests.yml):

    SECRETSENTINEL_TEST_RPC_URL=http://127.0.0.1:8545
    SECRETSENTINEL_TEST_REGISTRY=0x...

The publisher is the publicly known Hardhat development account #0 (derived
from the public test mnemonic). It must never be used on a real network.
"""

import copy
import os
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

pytest.importorskip("eth_account")

from eth_account import Account  # noqa: E402

from secretsentinel.core.errors import SecretSentinelError  # noqa: E402
from secretsentinel.fixtures import DEV_MNEMONIC  # noqa: E402
from secretsentinel.services import attestation as att  # noqa: E402
from secretsentinel.services import chain  # noqa: E402

RPC = os.environ.get("SECRETSENTINEL_TEST_RPC_URL")
REGISTRY = os.environ.get("SECRETSENTINEL_TEST_REGISTRY")
HARDHAT_CHAIN_ID = 31337

pytestmark = [
    pytest.mark.chain,
    pytest.mark.skipif(not (RPC and REGISTRY), reason="no local dev chain configured"),
]


@pytest.fixture(scope="module")
def dev_account():
    Account.enable_unaudited_hdwallet_features()
    return Account.from_mnemonic(DEV_MNEMONIC, account_path="m/44'/60'/0'/0/0")


def _scan(scan_id: str):
    return SimpleNamespace(
        id=scan_id, status="completed", secretsentinel_version="1.0.0", scanner_name="gitleaks",
        scanner_version="8.30.1", ruleset_digest="sha256:" + "a" * 64, policy_digest="sha256:" + "b" * 64,
        mode="both", scope="working-tree+full-history", policy_result="pass", fail_on="high",
        blocking_findings=0, total_findings=0, commit_sha="c" * 40,
        finished_at=datetime.now(timezone.utc),
    )


def test_register_and_verify_onchain(dev_account):
    assert chain.chain_id(chain.RpcClient(RPC)) == HARDHAT_CHAIN_ID
    payload, _ = att.build_payload(_scan(f"interop-{datetime.now().timestamp()}"), HARDHAT_CHAIN_ID)
    digest = att.digest_of(payload)
    signature, signer = att.sign_digest(digest, dev_account.key.hex())

    tx = chain.register(RPC, REGISTRY, digest, dev_account.key.hex(), HARDHAT_CHAIN_ID, wait_seconds=30)
    assert tx.startswith("0x") and len(tx) == 66

    lookup = chain.make_lookup(RPC, REGISTRY)
    result = att.verify(payload, signature, signer, (signer,), HARDHAT_CHAIN_ID, expected_digest=digest, onchain_lookup=lookup)
    assert result.verified, [c.__dict__ for c in result.checks if not c.ok]

    # Deterministic duplicate rule: a second registration is refused.
    with pytest.raises(SecretSentinelError):
        chain.register(RPC, REGISTRY, digest, dev_account.key.hex(), HARDHAT_CHAIN_ID, wait_seconds=30)

    # T15: a modified payload is not found on-chain and fails verification.
    tampered = copy.deepcopy(payload)
    tampered["blocking_findings_count"] = 3
    bad = att.verify(tampered, signature, signer, (signer,), HARDHAT_CHAIN_ID, expected_digest=digest, onchain_lookup=lookup)
    assert not bad.verified
    assert any(c.name == "onchain-registered" and not c.ok for c in bad.checks)


def test_unauthorized_publisher_cannot_register(dev_account):
    Account.enable_unaudited_hdwallet_features()
    outsider = Account.from_mnemonic(DEV_MNEMONIC, account_path="m/44'/60'/0'/0/5")
    payload, _ = att.build_payload(_scan(f"outsider-{datetime.now().timestamp()}"), HARDHAT_CHAIN_ID)
    with pytest.raises(SecretSentinelError):
        chain.register(RPC, REGISTRY, att.digest_of(payload), outsider.key.hex(), HARDHAT_CHAIN_ID, wait_seconds=30)


def test_wrong_chain_id_is_refused(dev_account):
    payload, _ = att.build_payload(_scan("wrong-chain"), HARDHAT_CHAIN_ID)
    with pytest.raises(SecretSentinelError):
        chain.register(RPC, REGISTRY, att.digest_of(payload), dev_account.key.hex(), 11155111, wait_seconds=5)
