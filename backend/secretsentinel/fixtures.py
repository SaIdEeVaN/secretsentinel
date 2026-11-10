"""Deterministic synthetic fixture generation.

Positive fixtures are committed only as templates (``*.tmpl``) containing
placeholders such as ``{{SYNTH:hex64:evm-env}}``. Real-looking values are
generated at test/demo time from a public, fixed derivation, so:

* no secret-shaped value is ever committed to Git (nothing for push
  protection or our own CI scan to trip over);
* every generated value is known in advance and can be used as a *canary*:
  tests search API responses, SQLite dumps, CLI output, CI logs and exports
  for these exact strings and fail if any appear (security invariant S1/S2).

All values are SYNTHETIC. They are derived from public labels, protect
nothing and must never be used to hold funds or access real systems.
"""

from __future__ import annotations

import hashlib
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .paths import find_rules_dir

PLACEHOLDER_RE = re.compile(r"\{\{SYNTH:([a-z0-9_]+):([A-Za-z0-9_.-]+)\}\}")

_HEX = "0123456789abcdef"
_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_UPPER_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# 64 words from the BIP-39 English list, all 3-8 letters. A synthetic phrase
# built from them will NOT generally have a valid BIP-39 checksum, which is
# fine: detection is context based and never validates phrases.
_WORDS = (
    "abandon ability able about above absent absorb abstract absurd abuse access "
    "accident account accuse achieve acid acoustic acquire across act action actor "
    "actress actual adapt add addict address adjust admit adult advance advice "
    "aerobic affair afford afraid again age agent agree ahead aim air airport "
    "aisle alarm album alcohol alert alien all alley allow almost alone alpha "
    "already also alter always amateur among amount"
).split()
assert len(_WORDS) == 64

# Publicly documented Hardhat/Anvil development mnemonic (not a secret).
DEV_MNEMONIC = " ".join(["test"] * 11 + ["junk"])

_DOMAIN = b"secretsentinel-synthetic-fixture-v1:"


def _stream(kind: str, label: str, n: int) -> bytes:
    """Return ``n`` deterministic pseudo-random bytes for ``kind``/``label``."""
    out = bytearray()
    counter = 0
    seed = _DOMAIN + kind.encode() + b":" + label.encode()
    while len(out) < n:
        out.extend(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(out[:n])


def _chars(kind: str, label: str, alphabet: str, n: int) -> str:
    data = _stream(kind, label, n)
    return "".join(alphabet[b % len(alphabet)] for b in data)


def _mnemonic(label: str, words: int) -> str:
    data = _stream("mnemonic", label, words)
    return " ".join(_WORDS[b % len(_WORDS)] for b in data)


def _pem_body(label: str) -> str:
    raw = _chars("pem", label, _BASE64, 64 * 6)
    return "\n".join(raw[i : i + 64] for i in range(0, len(raw), 64))


def synth(kind: str, label: str) -> str:
    """Generate the synthetic value for a placeholder kind and label."""
    generators = {
        "hex32": lambda: _chars("hex", label, _HEX, 32),
        "hex40": lambda: _chars("hex", label, _HEX, 40),
        "hex64": lambda: _chars("hex", label, _HEX, 64),
        "alnum20": lambda: _chars("alnum", label, _ALNUM, 20),
        "alnum32": lambda: _chars("alnum", label, _ALNUM, 32),
        "alnum36": lambda: _chars("alnum", label, _ALNUM, 36),
        "upper34": lambda: _chars("upper", label, _UPPER_ALNUM, 34),
        "aws_akid": lambda: "AKIA" + _chars("b32", label, _BASE32, 16),
        "b58_88": lambda: _chars("b58", label, _BASE58, 88),
        "xprv": lambda: "xprv" + _chars("b58", label, _BASE58, 107),
        "bytes64": lambda: ",".join(str(b) for b in _stream("bytes", label, 64)),
        "mnemonic12": lambda: _mnemonic(label, 12),
        "mnemonic24": lambda: _mnemonic(label, 24),
        "devmnemonic": lambda: DEV_MNEMONIC,
        "pem": lambda: _pem_body(label),
    }
    try:
        return generators[kind]()
    except KeyError:
        raise ValueError(f"unknown synthetic kind: {kind}") from None


def render(text: str, canaries: set[str] | None = None) -> str:
    """Replace every ``{{SYNTH:kind:label}}`` placeholder in ``text``."""

    def _sub(match: re.Match[str]) -> str:
        value = synth(match.group(1), match.group(2))
        if canaries is not None:
            canaries.add(value)
        return value

    return PLACEHOLDER_RE.sub(_sub, text)


@dataclass
class FixtureSet:
    root: Path
    canaries: set[str] = field(default_factory=set)
    manifest: dict = field(default_factory=dict)


def fixtures_dir() -> Path:
    return find_rules_dir() / "fixtures"


def load_manifest() -> dict:
    import yaml  # local import keeps module import cheap

    with open(fixtures_dir() / "manifest.yaml", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def materialize(dest: Path) -> FixtureSet:
    """Render all fixtures into ``dest`` (which must not already exist or be empty).

    Layout produced::

        dest/synthetic_positive/...   rendered templates (.tmpl suffix removed)
        dest/benign_negative/...      copied verbatim
    """
    src = fixtures_dir()
    dest.mkdir(parents=True, exist_ok=True)
    canaries: set[str] = set()
    for tmpl in sorted((src / "synthetic_positive").rglob("*")):
        if not tmpl.is_file():
            continue
        rel = tmpl.relative_to(src)
        target = dest / rel
        if target.name.endswith(".tmpl"):
            target = target.with_name(target.name[: -len(".tmpl")])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render(tmpl.read_text(encoding="utf-8"), canaries), encoding="utf-8")
    benign_src = src / "benign_negative"
    if benign_src.exists():
        shutil.copytree(benign_src, dest / "benign_negative", dirs_exist_ok=True)
    return FixtureSet(root=dest, canaries=canaries, manifest=load_manifest())


def all_canaries(extra_labels: bool = True) -> set[str]:
    """Every synthetic value produced by the fixture templates and the demo repo."""
    canaries: set[str] = set()
    for tmpl in (fixtures_dir() / "synthetic_positive").rglob("*"):
        if tmpl.is_file():
            render(tmpl.read_text(encoding="utf-8"), canaries)
    if extra_labels:
        from .services.demo import demo_canaries

        canaries |= demo_canaries()
    return canaries


def canary_fragments(canaries: set[str]) -> set[str]:
    """Return values plus distinctive prefixes/suffixes to catch partial leaks."""
    fragments: set[str] = set()
    for value in canaries:
        fragments.add(value)
        if len(value) >= 24 and value != DEV_MNEMONIC:
            fragments.add(value[:20])
            fragments.add(value[-20:])
    return fragments


def find_leaks(text: str, canaries: set[str]) -> list[str]:
    """Return a list of *masked* descriptions of canaries found in ``text``."""
    leaks = []
    for frag in sorted(canary_fragments(canaries)):
        if frag and frag in text:
            leaks.append(f"{frag[:4]}...({len(frag)} chars)")
    return leaks
