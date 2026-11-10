"""Sanitizer: deny-by-default field handling (PRD 12, test T10)."""

import json

import pytest

from secretsentinel.core.errors import ErrorCode, SecretSentinelError
from secretsentinel.fixtures import synth
from secretsentinel.services.sanitizer import (
    OUTSIDE_ROOT,
    REDACTED_PATH,
    SanitizeStats,
    normalize_path,
    sanitize_record,
    sanitize_report,
)

from .conftest import raw_record

CANARY = synth("hex64", "sanitizer-canary")


def _blob(finding) -> str:
    return json.dumps(finding.to_safe_dict())


def test_only_safe_fields_survive():
    stats = SanitizeStats()
    f = sanitize_record(raw_record(CANARY), "/repo", "dir", stats)
    d = f.to_safe_dict()
    assert d["rule_id"] == "web3-evm-private-key-assignment"
    assert d["relative_path"] == "src/config.js"
    assert d["start_line"] == 3
    for forbidden in ("secret", "match", "line", "message", "author", "email", "Secret", "Match"):
        assert forbidden not in d
    assert CANARY not in _blob(f)
    assert "someone@example.invalid" not in _blob(f)
    assert stats.redaction_failures == 1  # raw Secret was present -> flagged


def test_redacted_record_is_not_flagged_as_failure():
    stats = SanitizeStats()
    rec = raw_record(CANARY, Secret="REDACTED", Match="PRIVATE_KEY=REDACTED", Message="msg")
    sanitize_record(rec, "/repo", "dir", stats)
    assert stats.redaction_failures == 0


def test_unexpected_fields_are_dropped_and_counted_T10():
    stats = SanitizeStats()
    rec = raw_record(CANARY, NewSecretField=CANARY, Context={"line": CANARY}, Raw=[CANARY])
    f = sanitize_record(rec, "/repo", "dir", stats)
    assert stats.dropped_fields == 3
    assert CANARY not in _blob(f)


def test_secret_in_file_name_redacts_path():
    stats = SanitizeStats()
    rec = raw_record(CANARY, File=f"leaks/{CANARY}.txt")
    f = sanitize_record(rec, "/repo", "dir", stats)
    assert f.relative_path == REDACTED_PATH
    assert CANARY not in _blob(f)


@pytest.mark.parametrize(
    "raw,root,expected",
    [
        ("src/a.py", "/repo", "src/a.py"),
        ("./src/a.py", "/repo", "src/a.py"),
        ("src\\win\\a.py", "/repo", "src/win/a.py"),
        ("/repo/src/a.py", "/repo", "src/a.py"),
        ("/other/a.py", "/repo", OUTSIDE_ROOT),
        ("../escape.py", "/repo", OUTSIDE_ROOT),
        ("src/../../x", "/repo", OUTSIDE_ROOT),
        ("bad\nname\x1b[31m.py", "/repo", "bad?name?[31m.py"),
        ("", "/repo", ""),
    ],
)
def test_normalize_path(raw, root, expected):
    assert normalize_path(raw, root) == expected


@pytest.mark.parametrize(
    "override",
    [
        {"RuleID": None},
        {"RuleID": "Bad Rule ID!"},
        {"RuleID": "x" * 200},
        {"StartLine": "3"},
        {"StartLine": -1},
        {"StartLine": True},
        {"File": 42},
        {"Commit": 123},
    ],
)
def test_malformed_values_fail_closed(override):
    with pytest.raises(SecretSentinelError) as exc:
        sanitize_record(raw_record(CANARY, **override), "/repo", "dir", SanitizeStats())
    assert exc.value.code == ErrorCode.SANITIZATION_FAILED


def test_non_dict_record_and_non_list_report():
    with pytest.raises(SecretSentinelError):
        sanitize_record(["not", "a", "dict"], "/repo", "dir", SanitizeStats())
    with pytest.raises(SecretSentinelError) as exc:
        sanitize_report({"not": "a list"}, "/repo", "dir")
    assert exc.value.code == ErrorCode.REPORT_PARSE_FAILED


def test_invalid_commit_is_dropped_valid_is_kept():
    f = sanitize_record(raw_record(CANARY, Commit="not-a-sha"), "/repo", "git", SanitizeStats())
    assert f.commit_sha is None
    sha = "a" * 40
    f = sanitize_record(raw_record(CANARY, Commit=sha.upper()), "/repo", "git", SanitizeStats())
    assert f.commit_sha == sha


def test_tags_and_entropy_are_validated():
    f = sanitize_record(
        raw_record(CANARY, Tags=["web3", "x" * 100, 5, f"bad tag {CANARY}"], Entropy=float("nan")),
        "/repo", "dir", SanitizeStats(),
    )
    assert f.tags == ("web3",)
    assert f.entropy is None


def test_fingerprint_is_not_derived_from_secret():
    a = sanitize_record(raw_record(CANARY), "/repo", "dir", SanitizeStats())
    b = sanitize_record(raw_record(synth("hex64", "other")), "/repo", "dir", SanitizeStats())
    assert a.fingerprint == b.fingerprint  # same rule + location -> same id, independent of value
    assert a.fingerprint.startswith("ss1:")


def test_canary_detector_self_check(canaries):
    """Guard against a vacuous no-leak test: the detector must flag real canaries."""
    from secretsentinel.fixtures import find_leaks

    sample = sorted(canaries)[0]
    assert find_leaks(f"log line {sample} end", canaries)
    assert find_leaks(f"partial {sample[:20]}", canaries) or len(sample) < 24
    assert not find_leaks("nothing to see here", canaries)
