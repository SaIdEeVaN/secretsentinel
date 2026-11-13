"""scripts/audit_rules.py: samples strings from rule regexes, varies them, and reports
which assumptions a rule makes (literal runs, exact lengths, delimiters)."""

import importlib.util
import json
import re
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "audit_rules.py"
spec = importlib.util.spec_from_file_location("audit_rules", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

LITERAL_RULE = r"(?i)demotoken[ \t]*=[ \t]*(A{12}[a-z0-9]{30})(?:[\x60'" + '"' + r"\s;]|$)"


def test_sampler_produces_a_string_the_regex_accepts():
    text, runs = audit.sample(LITERAL_RULE, "demo-literal")
    assert re.search(LITERAL_RULE.replace("(?i)", ""), text, re.IGNORECASE)
    literal = [r for r in runs if r["literal"]]
    assert [(r["n"], r["in_secret"]) for r in literal] == [(12, True)]
    assert any(r["n"] == 30 and not r["literal"] for r in runs)


def test_sampler_is_deterministic_and_varies_one_repeat():
    a, runs = audit.sample(LITERAL_RULE, "demo-literal")
    assert a == audit.sample(LITERAL_RULE, "demo-literal")[0]
    run = next(r for r in runs if r["literal"])
    shorter, _ = audit.sample(LITERAL_RULE, "demo-literal", override={run["id"]: run["n"] - 1})
    assert len(shorter) == len(a) - 1 and not re.search(r"A{12}", shorter)


def test_sampler_handles_re2_only_syntax():
    # (?i) in the middle and \z are valid in Gitleaks (RE2) but not in Python's re.
    text, _ = audit.sample(r"prefix(?i)[a-z]{3}\z", "re2")
    assert text.startswith("prefix") and len(text) == 9


def test_analyse_separates_literal_runs_exact_lengths_and_delimiters():
    run_lit = {"id": 0, "n": 22, "literal": True, "in_secret": True}
    run_cls = {"id": 1, "n": 32, "literal": False, "in_secret": True}
    cases = [{"file": "f0", "rule": "r", "kind": "base", "label": "base"}]
    cases += [
        {"file": "f1", "rule": "r", "kind": "length", "label": "0m", "run": run_lit, "delta": -1},
        {"file": "f2", "rule": "r", "kind": "length", "label": "0p", "run": run_lit, "delta": 1},
        {"file": "f3", "rule": "r", "kind": "length", "label": "1m", "run": run_cls, "delta": -1},
        {"file": "f4", "rule": "r", "kind": "length", "label": "1p", "run": run_cls, "delta": 1},
        {"file": "f5", "rule": "r", "kind": "delimiter", "label": "&"},
        {"file": "f6", "rule": "r", "kind": "delimiter", "label": "space"},
        {"file": "g0", "rule": "undetected", "kind": "base", "label": "base"},
    ]
    fired = {"f0": {"r"}, "f2": {"r"}, "f6": {"r"}}
    result = audit.analyse(cases, fired)
    assert result["not_detected"] == ["undetected"] and result["detected"] == ["r"]
    assert result["literal_runs"] == [{"rule": "r", "n": 22, "shorter": False, "longer": True, "in_secret": True}]
    assert result["exact_length_rules"] == ["r"]  # both neighbours rejected
    assert result["delimiters_lost"] == {"&": ["r"]}
    # a class run that tolerates a longer value is not "exact"
    fired["f4"] = {"r"}
    assert audit.analyse(cases, fired)["exact_length_rules"] == []


@pytest.mark.gitleaks
def test_audit_end_to_end_on_a_tiny_config(tmp_path, gitleaks_bin, capsys):
    config = tmp_path / "rules.toml"
    config.write_text(
        'title = "audit demo"\n\n'
        "[[rules]]\n"
        'id = "demo-literal"\n'
        'description = "strict"\n'
        f"regex = '''{LITERAL_RULE}'''\n"
        'keywords = ["demotoken"]\n\n'
        "[[rules]]\n"
        'id = "demo-wide"\n'
        'description = "accepts more delimiters"\n'
        "regex = '''demowide=([a-z0-9]{20})(?:[&,)\\x60'\"\\s;]|$)'''\n"
        'keywords = ["demowide"]\n',
        encoding="utf-8",
    )
    out = tmp_path / "audit.json"
    assert audit.main(["--config", str(config), "--gitleaks", gitleaks_bin, "--json", str(out)]) == 0
    result = json.loads(out.read_text())
    assert result["detected"] == ["demo-literal", "demo-wide"]
    assert [(e["rule"], e["n"], e["shorter"]) for e in result["literal_runs"]] == [("demo-literal", 12, False)]
    assert set(result["exact_length_rules"]) == {"demo-literal", "demo-wide"}
    lost = result["delimiters_lost"]
    assert "demo-literal" in lost["&"] and "demo-wide" not in lost["&"]
    assert "demo-wide" in lost["/"]
    report = capsys.readouterr().out
    assert "demo-literal: exactly 12 in a row; one fewer is MISSED" in report
    assert "AAAAAAAAAAAA" not in report  # samples are never printed
