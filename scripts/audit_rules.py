#!/usr/bin/env python3
"""Look for near-miss gaps in Gitleaks rules with synthetic variants.

    python scripts/audit_rules.py --config gitleaks-default.toml --gitleaks /path/to/gitleaks
    python scripts/audit_rules.py --config rules/web3_rules.toml --gitleaks /path/to/gitleaks

For every rule with a regex the script builds one synthetic string the rule
should match (sampled from the regex itself, so it never contains a real
credential), checks that Gitleaks agrees, and then changes it slightly:

* **length**: every exact-count repeat (``X{22}``, ``[a-z0-9]{32}``) is made one
  shorter and one longer. A long run of one *literal* character is the shape
  that hid a real Twitter token (the default rule wants exactly 22 leading
  "A"s; real tokens also have 21).
* **delimiter**: the character after the value is replaced by ``&``, ``,``,
  ``)`` and so on. Most keyword rules only accept a quote, whitespace or ``;``.

Nothing here proves a real token is missed. It shows which assumptions a rule
makes, so a person can check them against the issuer's real format. The output
is a report; the exit status is 0 unless something cannot run. Samples are
written to a temporary directory and are never printed.

Needs Python 3.11+ (uses the regex parser in ``re._parser``) and a Gitleaks
binary. Get the default rules for the version you run with, for example:

    curl -sSL https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/config/gitleaks.toml -o gitleaks-default.toml
"""

from __future__ import annotations

import argparse
import json
import random
import re
import string
import subprocess
import sys
import tempfile
import tomllib
import warnings
from collections import defaultdict
from pathlib import Path

import re._constants as C  # noqa: E402 - private but stable since 3.11
import re._parser as sre_parse  # noqa: E402

warnings.filterwarnings("ignore")

MIN_EXACT_RUN = 6  # shorter exact counts are common and not interesting
BASELINE_TERMINATORS = {"space": " ", "single quote": "'", "double quote": '"', "semicolon": ";", "backtick": "`", "end of line": ""}
TEST_TERMINATORS = {"&": "&", ",": ",", ")": ")", "]": "]", "}": "}", "<": "<", "|": "|", "/": "/", ".": "."}
_ENDINGS = "`'\" ;"


def _category(cat) -> list[str]:
    name = str(cat)
    if "DIGIT" in name:
        return list(string.ascii_letters) if "NOT" in name else list(string.digits)
    if "WORD" in name:
        return list("-.:/+") if "NOT" in name else list(string.ascii_letters + string.digits + "_")
    if "SPACE" in name:
        return list(string.ascii_letters) if "NOT" in name else [" "]
    return list(string.ascii_letters)


def _set_chars(items) -> list[str]:
    negate, chars = False, set()
    for op, arg in items:
        if op is C.NEGATE:
            negate = True
        elif op is C.LITERAL:
            chars.add(chr(arg))
        elif op is C.RANGE:
            chars.update(chr(c) for c in range(arg[0], arg[1] + 1))
        elif op is C.CATEGORY:
            chars.update(_category(arg))
    if negate:
        return [c for c in string.ascii_letters + string.digits + "-_./+=%" if c not in chars] or ["~"]
    return sorted(chars)


class Sampler:
    """Generate a string that matches a regex, with optional repeat-count overrides."""

    def __init__(self, seed: str, secret_group: int, override: dict[int, int] | None = None):
        self.rng = random.Random(seed)
        self.secret_group = secret_group
        self.override = override or {}
        self.runs: list[dict] = []  # exact-count repeats found while generating
        self._repeat_id = 0

    def walk(self, nodes, in_secret=False) -> str:
        return "".join(self.node(op, arg, in_secret) for op, arg in nodes)

    def node(self, op, arg, in_secret) -> str:
        if op is C.LITERAL:
            return chr(arg)
        if op is C.NOT_LITERAL:
            return "~" if chr(arg) != "~" else "-"
        if op is C.ANY:
            return "x"
        if op is C.IN:
            return self.rng.choice(_set_chars(arg))
        if op is C.CATEGORY:
            return self.rng.choice(_category(arg))
        if op in (C.AT, C.GROUPREF, C.ASSERT, C.ASSERT_NOT):
            return ""
        if op is C.SUBPATTERN:
            group, _add, _del, sub = arg
            return self.walk(sub, in_secret or (group is not None and group == self.secret_group))
        if op is C.BRANCH:
            return self.walk(arg[1][0], in_secret)
        if op in (C.MAX_REPEAT, C.MIN_REPEAT, C.POSSESSIVE_REPEAT):
            low, high, sub = arg
            rid = self._repeat_id
            self._repeat_id += 1
            if low == high and low >= MIN_EXACT_RUN:
                literal = len(sub) == 1 and sub[0][0] is C.LITERAL
                self.runs.append({"id": rid, "n": low, "literal": literal, "in_secret": in_secret})
            if rid in self.override:
                count = self.override[rid]
            elif low == high:
                count = low
            else:
                count = low if low > 0 else (0 if self.rng.random() < 0.7 else 1)
            return "".join(self.walk(sub, in_secret) for _ in range(count))
        raise ValueError(f"unsupported regex element {op}")


def sample(regex: str, seed: str, secret_group: int | None = None, override: dict[int, int] | None = None):
    # RE2 allows (?i) anywhere and \z; Python does not. Case never matters for sampling.
    rx = re.sub(r"\(\?[imsU]+\)", "", regex.replace("\\z", "\\Z"))
    sampler = Sampler(seed, secret_group or 1, override)
    text = sampler.walk(sre_parse.parse(rx))
    return text, sampler.runs


def load_rules(config: Path) -> list[dict]:
    return [r for r in tomllib.loads(config.read_text(encoding="utf-8")).get("rules", []) if r.get("regex")]


def build_cases(rules: list[dict], out: Path):
    """Write every sample to ``out`` and return (cases, rules that could not be sampled)."""
    cases, skipped = [], []
    for idx, rule in enumerate(rules):
        rid, regex, group = rule["id"], rule["regex"], rule.get("secretGroup")
        try:
            base, runs = sample(regex, rid, group)
        except Exception as exc:  # noqa: BLE001 - report and move on
            skipped.append((rid, type(exc).__name__))
            continue

        def add(kind: str, label: str, text: str, **extra):
            name = f"case{len(cases):05d}.txt"  # labels contain characters that are not valid in file names
            (out / name).write_text("\n" + text + "\n", encoding="utf-8")
            cases.append({"file": name, "rule": rid, "kind": kind, "label": label, **extra})

        add("base", "base", base)
        for run in runs:
            for delta in (-1, 1):
                text, _ = sample(regex, rid, group, {run["id"]: run["n"] + delta})
                add("length", f"{run['id']}{'m' if delta < 0 else 'p'}", text, run=run, delta=delta)
        core = base[:-1] if base and base[-1] in _ENDINGS else base
        for label, ch in {**BASELINE_TERMINATORS, **TEST_TERMINATORS}.items():
            add("delimiter", label, core + ch)
    return cases, skipped


def scan(gitleaks: str, config: Path, folder: Path) -> dict[str, set[str]]:
    report = folder.parent / "audit-report.json"
    cmd = [gitleaks, "dir", str(folder), "-c", str(config), "--no-banner", "--redact=100", "-l", "error",
           "--exit-code", "0", "--report-format", "json", "--report-path", str(report)]
    subprocess.run(cmd, check=True, capture_output=True, timeout=900)
    fired: dict[str, set[str]] = defaultdict(set)
    for finding in json.loads(report.read_text(encoding="utf-8") or "[]"):
        fired[Path(finding["File"]).name].add(finding["RuleID"])
    return fired


def analyse(cases: list[dict], fired: dict[str, set[str]]) -> dict:
    hit = lambda c: c["rule"] in fired.get(c["file"], set())  # noqa: E731
    base_ok = {c["rule"] for c in cases if c["kind"] == "base" and hit(c)}
    all_rules = {c["rule"] for c in cases}
    literal: dict[tuple[str, int], dict] = {}
    classes: dict[tuple[str, int], dict[int, bool]] = defaultdict(dict)  # (rule, repeat id) -> {delta: detected}
    for c in cases:
        if c["kind"] != "length" or c["rule"] not in base_ok:
            continue
        run = c["run"]
        if run["literal"]:
            entry = literal.setdefault((c["rule"], run["n"]), {"shorter": None, "longer": None, "in_secret": run["in_secret"]})
            entry["shorter" if c["delta"] < 0 else "longer"] = hit(c)
        else:
            classes[(c["rule"], run["id"])][c["delta"]] = hit(c)
    exact = {rule for (rule, _), seen in classes.items() if not any(seen.values())}  # rejects both neighbours
    lost: dict[str, list[str]] = defaultdict(list)
    for c in cases:
        if c["kind"] == "delimiter" and c["rule"] in base_ok and not hit(c):
            lost[c["label"]].append(c["rule"])
    return {
        "rules": len(all_rules), "detected": sorted(base_ok), "not_detected": sorted(all_rules - base_ok),
        "literal_runs": [{"rule": r, "n": n, **v} for (r, n), v in sorted(literal.items())],
        "exact_length_rules": sorted(exact), "delimiters_lost": {k: sorted(set(v)) for k, v in lost.items()},
    }


def render(result: dict, skipped: list[tuple[str, str]], config: Path) -> str:
    n_ok = len(result["detected"])
    lines = [f"# Rule audit: {config.name}", "",
             f"- {result['rules'] + len(skipped)} rules with a regex; {n_ok} sampled and detected by their own rule.",
             f"- {len(result['not_detected'])} sampled but not detected (multi-line, entropy or context the sampler cannot build): "
             f"{', '.join(result['not_detected']) or 'none'}",
             f"- {len(skipped)} could not be sampled: {', '.join(f'{r} ({e})' for r, e in skipped) or 'none'}", ""]
    lines += ["## Runs of one literal character (a length assumption that is easy to get wrong)", ""]
    if result["literal_runs"]:
        for e in result["literal_runs"]:
            lines.append(f"- {e['rule']}: exactly {e['n']} in a row; one fewer is {'detected' if e['shorter'] else 'MISSED'}, "
                         f"one more is {'detected' if e['longer'] else 'missed'}")
    else:
        lines.append("- none")
    exact = result["exact_length_rules"]
    lines += ["", f"## Exact-length character runs ({len(exact)} rules reject both one shorter and one longer)", "",
              "Strict by design for fixed-length formats. Check these against the issuer's documentation; a format "
              "that is variable in practice needs a wider rule.", "", ", ".join(exact) or "none", ""]
    lines += [f"## Delimiter after the value ({n_ok} rules sampled)", "", "| after the value | rules that stop matching |", "|---|---|"]
    for label in [*BASELINE_TERMINATORS, *TEST_TERMINATORS]:
        lines.append(f"| {label} | {len(result['delimiters_lost'].get(label, []))} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", required=True, type=Path, help="Gitleaks rules file to audit (the default rules, or rules/web3_rules.toml)")
    ap.add_argument("--gitleaks", default="gitleaks", help="Gitleaks binary")
    ap.add_argument("--json", type=Path, help="also write the raw results here")
    ap.add_argument("--list-delimiters", action="store_true", help="name the rules that stop matching for each delimiter")
    args = ap.parse_args(argv)
    rules = load_rules(args.config)
    with tempfile.TemporaryDirectory(prefix="ss-audit-") as tmp:
        samples = Path(tmp) / "samples"
        samples.mkdir()
        cases, skipped = build_cases(rules, samples)
        fired = scan(args.gitleaks, args.config, samples)
    result = analyse(cases, fired)
    print(render(result, skipped, args.config))
    if args.list_delimiters:
        for label in TEST_TERMINATORS:
            print(f"### after {label!r}: {', '.join(result['delimiters_lost'].get(label, [])) or 'none'}\n")
    if args.json:
        args.json.write_text(json.dumps({**result, "skipped": skipped}, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
