"""Ruleset loading, digesting and effective Gitleaks config generation."""

from __future__ import annotations

import fnmatch
import hashlib
import tomllib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from ..core.errors import ErrorCode, SecretSentinelError
from ..core.security import glob_match, glob_to_regex
from ..paths import find_rules_dir
from .remediation import CATALOG

WEB3_RULES_FILE = "web3_rules.toml"
MAPPING_FILE = "severity_mapping.yaml"
_SEVERITIES = ("critical", "high", "medium", "low")
_CONFIDENCES = ("high", "medium", "low")


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    title: str
    severity: str
    confidence: str
    family: str
    remediation_key: str
    requirement: str | None = None
    description: str | None = None
    web3: bool = False
    source: str = "default"  # exact | pattern | default

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "family": self.family,
            "remediation_key": self.remediation_key,
            "requirement": self.requirement,
            "description": self.description,
            "web3": self.web3,
            "mapping_source": self.source,
        }


def _title_from_id(rule_id: str) -> str:
    return " ".join(part.capitalize() for part in rule_id.replace("_", "-").split("-") if part)


def _validate_entry(entry: dict, where: str) -> None:
    if entry.get("severity") not in _SEVERITIES:
        raise SecretSentinelError(ErrorCode.INVALID_CONFIG, f"Invalid severity in {where}.")
    if entry.get("confidence") not in _CONFIDENCES:
        raise SecretSentinelError(ErrorCode.INVALID_CONFIG, f"Invalid confidence in {where}.")
    if entry.get("remediation_key") not in CATALOG:
        raise SecretSentinelError(ErrorCode.INVALID_CONFIG, f"Unknown remediation key in {where}.")
    if not entry.get("family"):
        raise SecretSentinelError(ErrorCode.INVALID_CONFIG, f"Missing family in {where}.")


class Ruleset:
    def __init__(self, rules_dir: Path):
        self.rules_dir = rules_dir
        self.web3_rules_path = rules_dir / WEB3_RULES_FILE
        self.mapping_path = rules_dir / MAPPING_FILE
        try:
            self._toml_bytes = self.web3_rules_path.read_bytes()
            self._mapping_bytes = self.mapping_path.read_bytes()
            self.toml = tomllib.loads(self._toml_bytes.decode("utf-8"))
            self.mapping = yaml.safe_load(self._mapping_bytes.decode("utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, yaml.YAMLError):
            raise SecretSentinelError(ErrorCode.INVALID_CONFIG) from None
        if not isinstance(self.mapping, dict):
            raise SecretSentinelError(ErrorCode.INVALID_CONFIG)
        if not self.toml.get("extend", {}).get("useDefault"):
            # Guard against accidentally REPLACING the default Gitleaks rules.
            raise SecretSentinelError(ErrorCode.INVALID_CONFIG, "Ruleset must extend the Gitleaks defaults.")
        if "allowlist" in self.toml or "allowlists" in self.toml:
            # The generated config owns the top-level allowlist (policy exclusions).
            raise SecretSentinelError(ErrorCode.INVALID_CONFIG, "Ruleset must not define a global allowlist.")
        self.version = str(self.mapping.get("ruleset_version", "0"))
        self.defaults = dict(self.mapping.get("defaults") or {})
        _validate_entry(self.defaults, "defaults")
        self.exact: dict[str, dict] = {}
        for rule_id, entry in (self.mapping.get("rules") or {}).items():
            merged = {**self.defaults, **(entry or {})}
            _validate_entry(merged, f"rules.{rule_id}")
            self.exact[rule_id] = merged
        self.patterns: list[dict] = []
        for idx, entry in enumerate(self.mapping.get("patterns") or []):
            merged = {**self.defaults, **(entry or {})}
            if not merged.get("match"):
                raise SecretSentinelError(ErrorCode.INVALID_CONFIG, f"Missing match in patterns[{idx}].")
            _validate_entry(merged, f"patterns[{idx}]")
            self.patterns.append(merged)
        self.low_confidence_paths: tuple[str, ...] = tuple(self.mapping.get("low_confidence_paths") or ())
        self.custom_rules: dict[str, dict] = {}
        for rule in self.toml.get("rules", []):
            if rule.get("regex") or rule.get("path"):
                self.custom_rules[rule["id"]] = rule
        missing = [rid for rid in self.custom_rules if rid.startswith("web3-") and rid not in self.exact]
        if missing:
            raise SecretSentinelError(ErrorCode.INVALID_CONFIG, "Every Web3 rule needs a severity mapping.")

    @property
    def digest(self) -> str:
        h = hashlib.sha256()
        for name, data in ((WEB3_RULES_FILE, self._toml_bytes), (MAPPING_FILE, self._mapping_bytes)):
            h.update(name.encode() + b"\x00" + len(data).to_bytes(8, "big") + data)
        return "sha256:" + h.hexdigest()

    def meta(self, rule_id: str) -> RuleMeta:
        description = None
        web3 = rule_id.startswith("web3-")
        if rule_id in self.custom_rules:
            description = self.custom_rules[rule_id].get("description")
        if rule_id in self.exact:
            e, source = self.exact[rule_id], "exact"
        else:
            e, source = next(
                ((p, "pattern") for p in self.patterns if fnmatch.fnmatchcase(rule_id, p["match"])),
                (self.defaults, "default"),
            )
        return RuleMeta(
            rule_id=rule_id,
            title=e.get("title") or _title_from_id(rule_id),
            severity=e["severity"],
            confidence=e["confidence"],
            family=e["family"],
            remediation_key=e["remediation_key"],
            requirement=e.get("requirement"),
            description=description,
            web3=web3,
            source=source,
        )

    def is_low_confidence_path(self, path: str) -> bool:
        return any(glob_match(p, path) for p in self.low_confidence_paths)

    def list_rules(self) -> list[RuleMeta]:
        ids = sorted(set(self.exact) | set(self.custom_rules))
        return [self.meta(rid) for rid in ids]

    def effective_config(self, exclude_globs: tuple[str, ...] = ()) -> str:
        """Ruleset text plus a generated global allowlist for policy exclusions."""
        text = self._toml_bytes.decode("utf-8")
        if exclude_globs:
            regexes = []
            for glob in exclude_globs:
                rx = glob_to_regex(glob, descendants=True)
                if "'''" in rx:
                    raise SecretSentinelError(ErrorCode.INVALID_POLICY)
                regexes.append(f"    '''{rx}''',")
            text += (
                "\n\n# --- generated by SecretSentinel from policy exclude_paths ---\n"
                "[allowlist]\n"
                'description = "SecretSentinel policy exclusions"\n'
                "paths = [\n" + "\n".join(regexes) + "\n]\n"
            )
        try:
            tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            raise SecretSentinelError(ErrorCode.INVALID_CONFIG) from None
        return text


@lru_cache(maxsize=8)
def _load_cached(rules_dir: str, mtimes: tuple[float, float]) -> Ruleset:
    return Ruleset(Path(rules_dir))


def load_ruleset(rules_dir: Path | None = None) -> Ruleset:
    rd = (rules_dir or find_rules_dir()).resolve()
    try:
        mtimes = ((rd / WEB3_RULES_FILE).stat().st_mtime, (rd / MAPPING_FILE).stat().st_mtime)
    except OSError:
        raise SecretSentinelError(ErrorCode.INVALID_CONFIG) from None
    return _load_cached(str(rd), mtimes)
