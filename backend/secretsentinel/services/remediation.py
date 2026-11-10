"""Remediation guidance catalog.

Guidance is static, reviewed text keyed by ``remediation_key``. It never
references the detected value. Real credential rotation and incident response
remain human-directed (invariant S5): SecretSentinel never uses, validates,
revokes or moves anything with a detected credential.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Remediation:
    key: str
    title: str
    risk: str
    steps: tuple[str, ...]
    urgency: str = "high"
    notes: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "title": self.title,
            "risk": self.risk,
            "urgency": self.urgency,
            "steps": list(self.steps),
            "notes": list(self.notes),
        }


HISTORY_NOTE = (
    "Deleting the line or rewriting Git history does NOT revoke a credential. Forks, clones, "
    "CI caches and mirrors may still hold it. Rotate first, then decide whether to clean history."
)

GENERAL_INCIDENT_STEPS: tuple[str, ...] = (
    "Revoke or rotate the credential at its issuer.",
    "Audit recent usage of the credential for unexpected activity.",
    "Contain affected systems (disable sessions, tighten permissions).",
    "Remove the secret from current files and load it from a secret manager or environment variable instead.",
    "Assess Git history, forks, caches and CI logs for other copies.",
    "Document the response according to your incident process.",
    "Rescan to confirm the finding is no longer detected.",
)

CATALOG: dict[str, Remediation] = {
    r.key: r
    for r in [
        Remediation(
            key="ROTATE_SIGNING_KEY",
            title="Treat the signing key as compromised",
            risk=(
                "Anyone holding a blockchain private key can sign transactions as that account. "
                "On public chains, transfers are irreversible and bots sweep exposed keys within seconds."
            ),
            urgency="critical",
            steps=(
                "Assume the key is compromised if it was ever real; do not wait to see if it is abused.",
                "Create a NEW wallet/key on a trusted device (hardware wallet or secure key manager).",
                "Move funds, NFTs and token approvals to the new account where appropriate; revoke old ERC-20/NFT approvals.",
                "Transfer contract ownership, admin, minter, upgrader and multisig roles away from the old address.",
                "Revoke application, relayer or API access tied to the old key.",
                "Load signing keys from a keystore, hardware signer or secret manager, never from source files.",
                "Remove the value from the repository and rescan.",
            ),
            notes=(HISTORY_NOTE, "SecretSentinel never checks balances or uses the detected key."),
        ),
        Remediation(
            key="MIGRATE_WALLET_SEED",
            title="Treat the seed phrase as compromised",
            risk=(
                "A mnemonic recreates EVERY account derived from it. Exposure compromises all addresses "
                "in the wallet, on every chain."
            ),
            urgency="critical",
            steps=(
                "Generate a new seed phrase on a trusted device; never reuse the exposed phrase.",
                "Migrate funds and on-chain roles from all derived accounts to the new wallet.",
                "Revoke token approvals granted by the old accounts.",
                "Store seeds offline or in a hardware wallet; inject test mnemonics via environment variables.",
                "Remove the phrase from the repository and rescan.",
            ),
            notes=(
                HISTORY_NOTE,
                "Word count alone does not prove a phrase is a valid or funded seed; it is reported as a candidate.",
            ),
        ),
        Remediation(
            key="DEV_KEY_NOTICE",
            title="Publicly known development key - never use outside local development",
            risk=(
                "This is the default Hardhat/Anvil development mnemonic. It is public; any funds sent to its "
                "accounts on a real network are taken almost immediately."
            ),
            urgency="low",
            steps=(
                "Confirm it is only used for local development networks.",
                "Make sure no deployment script or production configuration falls back to it.",
            ),
        ),
        Remediation(
            key="ROTATE_RPC_KEY",
            title="Rotate the RPC / provider credential",
            risk=(
                "Provider keys can be abused to exhaust paid quotas, run up bills or impersonate your "
                "application. Some providers also expose account-level management with the same key."
            ),
            urgency="high",
            steps=(
                "Rotate or delete the key in the provider dashboard (Infura, Alchemy, QuickNode, Etherscan, ...).",
                "Restrict new keys by allowed origin, contract address or IP where the provider supports it.",
                "Keep backend keys server-side; frontend keys should be origin-restricted and low privilege.",
                "Remove the key from source and rescan.",
            ),
            notes=("A public RPC URL without a key is not a secret.", HISTORY_NOTE),
        ),
        Remediation(
            key="PROTECT_KEYSTORE",
            title="Remove the keystore and assess its password strength",
            risk=(
                "Encrypted keystores can be brute-forced offline. A weak or reused password makes the "
                "underlying key effectively exposed."
            ),
            urgency="medium",
            steps=(
                "Remove the keystore from the repository and add the pattern to .gitignore.",
                "If the password was weak, reused or also committed, treat the key as compromised (see signing-key guidance).",
                "Keep keystores in a protected location outside source control.",
            ),
            notes=(HISTORY_NOTE,),
        ),
        Remediation(
            key="ROTATE_API_TOKEN",
            title="Revoke and rotate the token",
            risk="Service tokens grant API access with the issuing account's privileges until revoked.",
            steps=GENERAL_INCIDENT_STEPS,
            notes=(HISTORY_NOTE,),
        ),
        Remediation(
            key="ROTATE_CLOUD_CREDENTIAL",
            title="Rotate the cloud credential and review account activity",
            risk="Cloud credentials can expose infrastructure, data and billing.",
            urgency="critical",
            steps=(
                "Deactivate and rotate the credential in the cloud console/IAM.",
                "Review audit logs (e.g. CloudTrail / Cloud Audit Logs) for activity since the commit date.",
                "Scope replacement credentials to least privilege; prefer short-lived, federated credentials.",
            )
            + GENERAL_INCIDENT_STEPS[3:],
            notes=(HISTORY_NOTE,),
        ),
        Remediation(
            key="ROTATE_EXCHANGE_KEY",
            title="Revoke the exchange API key immediately",
            risk="Exchange API keys may allow trading or withdrawals from custodial accounts.",
            urgency="critical",
            steps=(
                "Delete the API key in the exchange account settings.",
                "Review recent orders, withdrawals and whitelisted addresses.",
                "Create a replacement key with withdrawals disabled and an IP allowlist.",
            )
            + GENERAL_INCIDENT_STEPS[3:],
            notes=(HISTORY_NOTE,),
        ),
        Remediation(
            key="ROTATE_PRIVATE_KEY_FILE",
            title="Replace the private key and its certificate/authorized keys",
            risk="Private key files can impersonate servers, sign artifacts or grant SSH access.",
            urgency="high",
            steps=(
                "Generate a new key pair.",
                "Revoke/reissue certificates and remove the old public key from authorized_keys, deploy keys and trust stores.",
            )
            + GENERAL_INCIDENT_STEPS[3:],
            notes=(HISTORY_NOTE,),
        ),
        Remediation(
            key="REVIEW_GENERIC_SECRET",
            title="Review the candidate secret",
            risk="A generic pattern matched a secret-like assignment. It may be a real credential or benign data.",
            urgency="medium",
            steps=(
                "Determine whether the value is a real credential.",
                "If real, follow the standard incident steps: rotate, audit, contain, remove, rescan.",
                "If benign, record a reviewed suppression with a justification and expiry date.",
            ),
        ),
        Remediation(
            key="REVIEW_IGNORE_FILE",
            title="Move scanner exceptions into reviewed SecretSentinel suppressions",
            risk=(
                "Gitleaks always honours a .gitleaksignore file in the scanned directory. Anyone who can change "
                "that file (for example in a pull request) can silently exempt a real secret from the gate."
            ),
            urgency="high",
            steps=(
                "Review every entry in .gitleaksignore; treat unexplained entries as potential cover for a leak.",
                "Re-create legitimate exceptions as suppressions in .secretsentinel.yml with a reason, reviewer and expiry.",
                "Delete .gitleaksignore and protect .secretsentinel.yml with CODEOWNERS review.",
                "If the ignore file must stay (e.g. for another tool), add a reviewed suppression for this finding.",
            ),
        ),
        Remediation(
            key="REVIEW_PUBLIC_IDENTIFIER",
            title="Confirm the identifier is meant to be public",
            risk="Client IDs and publishable keys are usually public but may reveal account structure.",
            urgency="low",
            steps=(
                "Confirm the value is a public/publishable identifier and not its paired secret.",
                "If it is intended to be public, add a reviewed suppression with an expiry date.",
            ),
        ),
    ]
}


def get_remediation(key: str | None) -> Remediation:
    if key and key in CATALOG:
        return CATALOG[key]
    return CATALOG["REVIEW_GENERIC_SECRET"]
