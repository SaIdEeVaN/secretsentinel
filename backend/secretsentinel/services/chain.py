"""P2 (optional): minimal Ethereum JSON-RPC client for the ScanRegistry contract.

Uses only urllib + eth-account (for signing/keccak). Only the 32-byte
attestation digest is ever sent on-chain.
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from typing import Any

from ..core.errors import ErrorCode, SecretSentinelError

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_DIGEST_RE = re.compile(r"^0x[0-9a-f]{64}$")


def _keccak(data: bytes) -> bytes:
    from eth_utils import keccak

    return keccak(data)


def selector(signature: str) -> str:
    return "0x" + _keccak(signature.encode()).hex()[:8]


def event_topic() -> str:
    return "0x" + _keccak(b"AttestationRegistered(bytes32,address,uint256)").hex()


class RpcClient:
    def __init__(self, url: str, timeout: int = 20):
        if not url or not url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
            raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "RPC URL must use HTTPS (or local loopback).")
        self.url = url
        self.timeout = timeout
        self._id = 0

    def call(self, method: str, params: list) -> Any:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json", "User-Agent": "secretsentinel"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 - scheme validated above
                data = json.loads(resp.read(2_000_000).decode("utf-8"))
        except Exception:  # noqa: BLE001 - do not echo RPC URLs (may embed keys)
            raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "RPC request failed.") from None
        if "error" in data:
            raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "RPC returned an error.")
        return data.get("result")


def _check_inputs(contract: str, digest: str) -> None:
    if not _ADDRESS_RE.match(contract or ""):
        raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "Invalid contract address.")
    if not _DIGEST_RE.match(digest or ""):
        raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "Invalid digest.")


def chain_id(rpc: RpcClient) -> int:
    return int(rpc.call("eth_chainId", []), 16)


def get_attestation(rpc: RpcClient, contract: str, digest: str) -> tuple[str | None, int]:
    _check_inputs(contract, digest)
    data = selector("getAttestation(bytes32)") + digest[2:]
    result = rpc.call("eth_call", [{"to": contract, "data": data}, "latest"])
    if not isinstance(result, str) or len(result) < 2 + 128:
        raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "Unexpected registry response.")
    publisher = "0x" + result[2 + 24 : 2 + 64]
    timestamp = int(result[2 + 64 : 2 + 128], 16)
    if int(publisher, 16) == 0:
        return None, 0
    return publisher, timestamp


def make_lookup(rpc_url: str, contract: str):
    def lookup(digest: str):
        rpc = RpcClient(rpc_url)
        publisher, _ts = get_attestation(rpc, contract, digest)
        return chain_id(rpc), contract, publisher

    return lookup


def register(rpc_url: str, contract: str, digest: str, private_key: str, expected_chain_id: int, wait_seconds: int = 180) -> str:
    """Send registerAttestation(digest); return the tx hash after a successful receipt."""
    from eth_account import Account

    _check_inputs(contract, digest)
    rpc = RpcClient(rpc_url)
    cid = chain_id(rpc)
    if cid != expected_chain_id:
        raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "RPC chain id does not match ATTESTATION_CHAIN_ID.")
    acct = Account.from_key(private_key)
    publisher, _ = get_attestation(rpc, contract, digest)
    if publisher is not None:
        raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "Digest is already registered.")
    data = selector("registerAttestation(bytes32)") + digest[2:]
    nonce = int(rpc.call("eth_getTransactionCount", [acct.address, "pending"]), 16)
    block = rpc.call("eth_getBlockByNumber", ["latest", False]) or {}
    base_fee = int(block.get("baseFeePerGas", "0x0"), 16)
    try:
        tip = int(rpc.call("eth_maxPriorityFeePerGas", []), 16)
    except SecretSentinelError:
        tip = 1_500_000_000
    gas = int(rpc.call("eth_estimateGas", [{"from": acct.address, "to": contract, "data": data}]), 16)
    tx = {
        "type": 2,
        "chainId": cid,
        "nonce": nonce,
        "to": contract,
        "value": 0,
        "data": data,
        "gas": int(gas * 1.2) + 1000,
        "maxPriorityFeePerGas": tip,
        "maxFeePerGas": base_fee * 2 + tip,
    }
    signed = acct.sign_transaction(tx)
    raw = signed.raw_transaction.hex()
    tx_hash = rpc.call("eth_sendRawTransaction", [raw if raw.startswith("0x") else "0x" + raw])
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        receipt = rpc.call("eth_getTransactionReceipt", [tx_hash])
        if receipt:
            if receipt.get("status") != "0x1":
                raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "Registration transaction reverted.")
            topic = event_topic()
            if not any(log.get("topics", [None])[0] == topic and log.get("topics", [None, None])[1] == digest for log in receipt.get("logs", [])):
                raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "Registration event not found in receipt.")
            return tx_hash
        time.sleep(4)
    raise SecretSentinelError(ErrorCode.ATTESTATION_ERROR, "Timed out waiting for the transaction; retry verification later.")
