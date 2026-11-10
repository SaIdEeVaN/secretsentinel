"""Ruleset integrity and detection quality on the versioned fixture set.

Acceptance targets (PRD 4.3): >= 90% detection on synthetic positives and
<= 10% false positives on benign negatives. Also covers T02, T05, T06, T07.
"""

import re
import tomllib
from pathlib import Path

import pytest

from secretsentinel.core.config import Settings
from secretsentinel.paths import find_rules_dir
from secretsentinel.services.remediation import CATALOG
from secretsentinel.services.rules import load_ruleset
from secretsentinel.services.scanner import ScanRequest, run_scan

RULES_DIR = find_rules_dir()
GO_UNSUPPORTED = [r"\(\?=", r"\(\?!", r"\(\?<=", r"\(\?<!", r"\\[1-9]", r"\(\?P=", r"\(\?>"]


def _toml():
    return tomllib.loads((RULES_DIR / "web3_rules.toml").read_text(encoding="utf-8"))


def test_ruleset_extends_defaults_and_has_no_global_allowlist():
    data = _toml()
    assert data["extend"]["useDefault"] is True
    assert "allowlist" not in data and "allowlists" not in data


def test_rule_ids_unique_and_not_generic():
    ids = [r["id"] for r in _toml()["rules"] if r.get("regex") or r.get("path")]
    assert len(ids) == len(set(ids))
    for rid in ids:
        assert rid.startswith("web3-")
        assert "generic" not in rid  # Gitleaks would drop overlapping generic-* findings


def test_regexes_avoid_go_unsupported_syntax():
    for rule in _toml()["rules"]:
        for key in ("regex", "path"):
            rx = rule.get(key)
            if not rx:
                continue
            for bad in GO_UNSUPPORTED:
                assert not re.search(bad, rx), f"{rule['id']}.{key} uses Go-unsupported syntax {bad}"
            # Must at least compile in Python too (\z -> \Z is the only translation needed).
            re.compile(rx.replace("\\z", "\\Z"))


def test_every_web3_rule_is_mapped_with_valid_remediation():
    rs = load_ruleset()
    for rid in rs.custom_rules:
        meta = rs.meta(rid)
        assert meta.source == "exact", rid
        assert meta.remediation_key in CATALOG
        assert meta.requirement and meta.requirement.startswith("W3-")


def test_mapping_resolution_order():
    rs = load_ruleset()
    assert rs.meta("aws-access-token").family == "cloud-credential"
    assert rs.meta("coinbase-access-token").remediation_key == "ROTATE_EXCHANGE_KEY"
    assert rs.meta("discord-client-id").severity == "low"
    assert rs.meta("some-unknown-rule").severity == rs.defaults["severity"]
    assert rs.meta("generic-api-key").severity == "medium"


def test_ruleset_digest_is_stable_and_content_bound(tmp_path):
    rs = load_ruleset()
    assert rs.digest == load_ruleset().digest and rs.digest.startswith("sha256:")
    copy = tmp_path / "rules"
    copy.mkdir()
    for name in ("web3_rules.toml", "severity_mapping.yaml"):
        (copy / name).write_bytes((RULES_DIR / name).read_bytes())
    assert load_ruleset(copy).digest == rs.digest
    with open(copy / "severity_mapping.yaml", "a", encoding="utf-8") as fh:
        fh.write("\n# changed\n")
    assert load_ruleset(copy).digest != rs.digest


def test_effective_config_appends_policy_exclusions():
    rs = load_ruleset()
    text = rs.effective_config(("node_modules", "rules/fixtures/**"))
    data = tomllib.loads(text)
    assert len(data["allowlist"]["paths"]) == 2


# --------------------------------------------------------------------------
# Detection quality with the REAL Gitleaks engine
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def fixture_scan(request, tmp_path_factory):
    gl = request.getfixturevalue("gitleaks_bin")
    root = request.getfixturevalue("fixture_root")
    settings = Settings(gitleaks_path=gl, db_url="sqlite://")
    outcome = run_scan(ScanRequest(target=root, mode="dir", timeout_seconds=120), settings)
    assert outcome.status == "completed", outcome.error_code
    return outcome


@pytest.mark.gitleaks
def test_detection_rate_and_false_positive_rate(fixture_scan, fixture_set):
    manifest = fixture_set.manifest
    found = {}
    for f in fixture_scan.findings:
        found.setdefault(f.relative_path, set()).update({f.rule_id, *f.also_matched})
    positives = manifest["positives"]
    detected = [p for p in positives if p["rule"] in found.get(p["path"], set())]
    missed = [p["path"] for p in positives if p not in detected]
    rate = len(detected) / len(positives)
    negatives = manifest["negatives"]
    false_pos = [n["path"] for n in negatives if n["path"] in found]
    fp_rate = len(false_pos) / len(negatives)
    print(f"\ndetection={rate:.0%} ({len(detected)}/{len(positives)}) fp={fp_rate:.0%} ({len(false_pos)}/{len(negatives)})")
    assert rate >= 0.90, f"missed: {missed}"
    assert fp_rate <= 0.10, f"false positives: {false_pos}"


@pytest.mark.gitleaks
def test_T06_private_key_assignment_is_critical(fixture_scan):
    f = next(f for f in fixture_scan.findings if f.relative_path.endswith("evm/env_private_key.env"))
    assert f.rule_id == "web3-evm-private-key-assignment"
    assert f.severity == "critical" and f.blocking
    assert "generic-api-key" in f.also_matched  # overlap merged, not duplicated (SCAN-07)


@pytest.mark.gitleaks
def test_T05_T07_hashes_and_sentences_not_signing_secrets(fixture_scan):
    for f in fixture_scan.findings:
        if f.relative_path.startswith("benign_negative/"):
            assert f.family not in ("web3-signing-key", "web3-mnemonic"), f.relative_path


@pytest.mark.gitleaks
def test_T02_service_tokens_detected(fixture_scan):
    rules = {f.rule_id for f in fixture_scan.findings if f.relative_path.startswith("synthetic_positive/services/")}
    assert {"aws-access-token", "github-pat", "private-key"} <= rules


@pytest.mark.gitleaks
def test_known_dev_mnemonic_is_low_not_critical(fixture_scan):
    f = next(f for f in fixture_scan.findings if f.relative_path.endswith("hardhat_dev.config.js"))
    assert f.rule_id == "web3-known-dev-mnemonic"
    assert f.severity == "low" and not f.blocking


@pytest.mark.gitleaks
def test_no_duplicate_cards_per_occurrence(fixture_scan):
    keys = [(f.relative_path, f.start_line, f.commit_sha) for f in fixture_scan.findings]
    assert len(keys) == len(set(keys))


def test_fixture_templates_contain_no_raw_values():
    """Positive fixtures are committed as templates only (no secret-shaped values in Git)."""
    tmpl_dir = RULES_DIR / "fixtures" / "synthetic_positive"
    hex64 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
    for path in Path(tmpl_dir).rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            assert "{{SYNTH:" in text or path.suffix == ".tmpl", path
            assert not hex64.search(text), f"raw 64-hex value committed in {path}"


def _crlf_rules_copy(tmp_path):
    copy = tmp_path / "rules-crlf"
    copy.mkdir()
    for name in ("web3_rules.toml", "severity_mapping.yaml"):
        data = (RULES_DIR / name).read_bytes().replace(b"\r\n", b"\n")
        (copy / name).write_bytes(data.replace(b"\n", b"\r\n"))
    return copy


def test_crlf_checkout_has_same_digest_and_clean_config(tmp_path):
    """Windows checkouts convert to CRLF; the digest must not change and the
    generated config must not contain CR (regression: Windows CI INVALID_CONFIG)."""
    crlf = load_ruleset(_crlf_rules_copy(tmp_path))
    assert crlf.digest == load_ruleset().digest
    assert "\r" not in crlf.effective_config(("node_modules",))


@pytest.mark.gitleaks
def test_scan_works_with_crlf_ruleset(tmp_path, gitleaks_bin):
    target = tmp_path / "t"
    target.mkdir()
    (target / "a.env").write_text("DEPLOYER_PRIVATE_KEY=0x" + "0123456789abcdef" * 4 + "\n")
    rs = load_ruleset(_crlf_rules_copy(tmp_path))
    o = run_scan(ScanRequest(target=target, mode="dir"), Settings(gitleaks_path=gitleaks_bin, db_url="sqlite://"), ruleset=rs)
    assert o.status == "completed", o.error_code
    assert o.blocking_findings == 1
