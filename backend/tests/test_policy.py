"""Blocking policy, reviewed suppressions, expiry and baselines (FIND-06/07, CI-07, T11)."""

import json
from datetime import date, timedelta

import pytest

from secretsentinel.core.errors import ErrorCode, SecretSentinelError
from secretsentinel.services.policy import Suppression, build_baseline, discover_policy, evaluate, load_policy
from secretsentinel.services.types import SafeFinding, ScanOutcome

TODAY = date(2026, 11, 10)


def _finding(sev="critical", rule="web3-evm-private-key-assignment", path="src/a.js", line=3, commit=None):
    return SafeFinding(rule_id=rule, relative_path=path, start_line=line, end_line=line, severity=sev, commit_sha=commit)


def _outcome(*findings, status="completed"):
    return ScanOutcome(mode="dir", status=status, findings=list(findings))


def _sup(**kw):
    base = dict(id="S1", rule_id="web3-evm-private-key-assignment", path="src/*.js", reason="Reviewed synthetic test value",
                reviewer="alice", expires=TODAY + timedelta(days=30))
    base.update(kw)
    return Suppression(**base)


@pytest.mark.parametrize(
    "fail_on,sev,blocking",
    [("high", "critical", True), ("high", "high", True), ("high", "medium", False), ("medium", "medium", True),
     ("critical", "high", False), ("low", "low", True), ("none", "critical", False)],
)
def test_threshold(fail_on, sev, blocking):
    o = _outcome(_finding(sev))
    evaluate(o, fail_on, [], TODAY)
    assert o.findings[0].blocking is blocking
    assert o.policy_result == ("fail" if blocking else "pass")


def test_failed_scan_is_never_pass_S3():
    for status in ("failed", "cancelled"):
        o = _outcome(status=status)
        evaluate(o, "high", [], TODAY)
        assert o.policy_result == "not_evaluated"


def test_valid_suppression_applies():
    o = _outcome(_finding())
    evaluate(o, "high", [_sup()], TODAY)
    assert o.findings[0].status == "suppressed" and not o.findings[0].blocking
    assert o.policy_result == "pass"


@pytest.mark.parametrize(
    "override,problem",
    [
        ({"reason": None}, "missing-reason"),
        ({"reason": "too short"}, "missing-reason"),
        ({"reviewer": ""}, "missing-reviewer"),
        ({"expires": None}, "missing-expiry"),
        ({"expires": TODAY - timedelta(days=1)}, "expired"),
        ({"expires": TODAY + timedelta(days=400)}, "expiry-too-far"),
        ({"path": None}, "missing-scope"),
        ({"rule_id": None}, "missing-or-invalid-rule"),
    ],
)
def test_T11_unreviewed_or_expired_suppression_does_not_apply(override, problem):
    o = _outcome(_finding())
    evaluate(o, "high", [_sup(**override)], TODAY)
    assert o.findings[0].blocking and o.policy_result == "fail"
    assert any(problem in w for w in o.warnings)


def test_suppression_scope_is_narrow():
    o = _outcome(_finding(path="other/a.js"), _finding(rule="aws-access-token", sev="high"))
    evaluate(o, "high", [_sup()], TODAY)
    assert all(f.blocking for f in o.findings)


def test_policy_file_loading(tmp_path):
    (tmp_path / ".secretsentinel.yml").write_text(
        "version: 1\nfail_on: critical\nexclude_paths: [node_modules, 'dist/**']\n"
        "suppressions:\n  - id: SUP-1\n    rule_id: generic-api-key\n    path: 'docs/**'\n"
        "    reason: Documented placeholder values\n    reviewer: bob\n    expires: 2027-01-31\n"
    )
    p = discover_policy(tmp_path)
    assert p.fail_on == "critical" and p.exclude_paths == ("node_modules", "dist/**")
    assert p.suppressions[0].expires == date(2027, 1, 31)
    assert p.digest.startswith("sha256:")


@pytest.mark.parametrize(
    "content",
    [
        "fail_on: extreme\n",
        "unknown_key: 1\n",
        "version: 2\n",
        "exclude_paths: notalist\n",
        "suppressions:\n  - rule_id: x\n",
        "suppressions:\n  - {id: A, rule_id: x, path: y, commit: nothex}\n",
        "suppressions:\n  - {id: A, rule_id: x, path: y}\n  - {id: A, rule_id: x, path: z}\n",
        "baseline: ../../etc/passwd\n",
        ": [",
    ],
)
def test_invalid_policy_fails_closed(tmp_path, content):
    f = tmp_path / ".secretsentinel.yml"
    f.write_text(content)
    with pytest.raises(SecretSentinelError) as e:
        load_policy(f)
    assert e.value.code == ErrorCode.INVALID_POLICY


def test_baseline_roundtrip(tmp_path):
    old = _finding(path="legacy/x.js", line=10, commit="b" * 40)
    baseline = build_baseline([old], "Pre-existing findings tracked in SEC-12", "carol", date.today() + timedelta(days=90), "sha256:x")
    for entry in baseline["entries"]:
        assert set(entry) == {"rule_id", "relative_path", "start_line", "commit_sha", "fingerprint"}
    (tmp_path / "bl.json").write_text(json.dumps(baseline))
    (tmp_path / ".secretsentinel.yml").write_text("baseline: bl.json\n")
    policy = discover_policy(tmp_path)
    # Same rule/path/line but seen in dir mode (no commit): still matches.
    o = _outcome(_finding(path="legacy/x.js", line=10), _finding(path="new/y.js"))
    evaluate(o, "high", policy.suppressions)
    assert [f.status for f in o.findings] == ["suppressed", "open"]
    assert o.policy_result == "fail"  # new leak still blocks (CI-07)


def test_baseline_requires_review_metadata():
    with pytest.raises(SecretSentinelError):
        build_baseline([], "short", "", date.today() + timedelta(days=10), None)
