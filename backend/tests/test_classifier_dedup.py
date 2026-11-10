"""Classification boundaries, remediation mapping and deduplication (SCAN-07)."""

from secretsentinel.services.deduplicator import deduplicate
from secretsentinel.services.finding_classifier import classify
from secretsentinel.services.remediation import CATALOG, get_remediation
from secretsentinel.services.rules import load_ruleset
from secretsentinel.services.types import SafeFinding


def _f(rule, path="src/a.js", line=1, commit=None, sources=("dir",), entropy=3.9):
    return SafeFinding(rule_id=rule, relative_path=path, start_line=line, end_line=line, commit_sha=commit,
                       sources=sources, entropy=entropy)


def test_test_paths_lower_confidence_not_severity():
    rs = load_ruleset()
    prod = classify(_f("web3-evm-private-key-assignment"), rs)
    test = classify(_f("web3-evm-private-key-assignment", path="backend/tests/fixtures/k.env"), rs)
    assert prod.severity == test.severity == "critical"
    assert prod.confidence == "high" and test.confidence == "medium"


def test_low_entropy_lowers_confidence():
    rs = load_ruleset()
    f = classify(_f("aws-access-token", entropy=2.1), rs)
    assert f.confidence == "medium"


def test_every_remediation_has_steps():
    for key, rem in CATALOG.items():
        assert rem.steps and rem.title and rem.risk, key
    assert get_remediation("nope").key == "REVIEW_GENERIC_SECRET"


def test_signing_key_guidance_mentions_migration():
    text = " ".join(get_remediation("ROTATE_SIGNING_KEY").steps).lower()
    assert "new wallet" in text and "approvals" in text


def test_overlapping_rules_merge_keeping_most_specific():
    rs = load_ruleset()
    a = classify(_f("generic-api-key"), rs)
    b = classify(_f("web3-evm-private-key-assignment"), rs)
    out = deduplicate([a, b])
    assert len(out) == 1
    assert out[0].rule_id == "web3-evm-private-key-assignment" and out[0].also_matched == ("generic-api-key",)


def test_dir_and_git_occurrence_merge():
    rs = load_ruleset()
    d = classify(_f("aws-access-token", sources=("dir",)), rs)
    g = classify(_f("aws-access-token", commit="c" * 40, sources=("git",)), rs)
    out = deduplicate([d, g])
    assert len(out) == 1 and out[0].sources == ("dir", "git") and out[0].commit_sha == "c" * 40


def test_same_text_in_two_commits_stays_distinct():
    rs = load_ruleset()
    a = classify(_f("aws-access-token", commit="a" * 40, sources=("git",)), rs)
    b = classify(_f("aws-access-token", commit="b" * 40, sources=("git",)), rs)
    assert len(deduplicate([a, b])) == 2


def test_exact_duplicates_collapse():
    rs = load_ruleset()
    out = deduplicate([classify(_f("github-pat"), rs), classify(_f("github-pat"), rs)])
    assert len(out) == 1


def test_results_sorted_by_severity():
    rs = load_ruleset()
    out = deduplicate([classify(_f("generic-api-key", path="z"), rs), classify(_f("web3-mnemonic-assignment", path="a"), rs)])
    assert out[0].severity == "critical"
