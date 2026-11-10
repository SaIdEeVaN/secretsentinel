"""Sanitized report exporters: text, JSON, SARIF 2.1.0, CSV, GitHub Actions.

All exporters consume ``ScanOutcome``/``SafeFinding`` objects, which contain no
secret material by construction. The target is identified by its directory
name only, so exported reports do not disclose local absolute paths.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Iterable

from .. import __version__
from ..core.errors import safe_message
from .remediation import get_remediation
from .types import ScanOutcome

REPORT_SCHEMA = "secretsentinel-report/v1"
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SEV_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}

CLEAN_MESSAGE = "No matching secrets detected in the scanned scope."
FAILED_MESSAGE = "Scan could not complete; security status is unknown."
SCOPE_NOTE = "A clean result means no rule matched in the scanned scope; it is not a guarantee that no secrets exist."


def _iso(dt) -> str | None:
    return dt.isoformat() if dt else None


def report_dict(outcome: ScanOutcome, target_name: str) -> dict:
    return {
        "schema": REPORT_SCHEMA,
        "tool": {
            "name": "SecretSentinel",
            "version": outcome.secretsentinel_version or __version__,
            "scanner": outcome.scanner_name,
            "scanner_version": outcome.scanner_version,
            "ruleset_version": outcome.ruleset_version,
            "ruleset_digest": outcome.ruleset_digest,
            "policy_digest": outcome.policy_digest,
        },
        "scan": {
            "target": target_name,
            "mode": outcome.mode,
            "scope": outcome.scope,
            "status": outcome.status,
            "error_code": outcome.error_code,
            "error_message": safe_message(outcome.error_code),
            "policy_result": outcome.policy_result,
            "fail_on": outcome.fail_on,
            "commit_sha": outcome.commit_sha,
            "started_at": _iso(outcome.started_at),
            "finished_at": _iso(outcome.finished_at),
            "total_findings": outcome.total_findings,
            "blocking_findings": outcome.blocking_findings,
            "suppressed_findings": outcome.suppressed_findings,
            "severity_counts": outcome.severity_counts(),
            "warnings": list(outcome.warnings),
        },
        "findings": [f.to_safe_dict() for f in outcome.findings],
    }


def to_json(outcome: ScanOutcome, target_name: str) -> str:
    return json.dumps(report_dict(outcome, target_name), indent=2, sort_keys=False) + "\n"


def to_sarif(outcome: ScanOutcome, target_name: str) -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in outcome.findings:
        if f.rule_id not in rules:
            rem = get_remediation(f.remediation_key)
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.title or f.rule_id},
                "help": {"text": rem.title + ". " + " ".join(rem.steps[:3])},
                "properties": {"family": f.family, "security-severity": {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "2.0"}[f.severity]},
            }
        region = {"startLine": max(1, f.start_line)}
        if f.start_column:
            region["startColumn"] = f.start_column
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f"{f.title} (severity {f.severity}, confidence {f.confidence}). Secret value redacted."},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.relative_path or "."}, "region": region}}],
                "partialFingerprints": {"secretsentinel/v1": f.fingerprint},
                "properties": {
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "status": f.status,
                    "blocking": f.blocking,
                    "commit": f.commit_sha,
                },
                **({"suppressions": [{"kind": "external", "justification": f"suppression {f.suppression_id}"}]} if f.status == "suppressed" else {}),
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecretSentinel",
                        "version": outcome.secretsentinel_version or __version__,
                        "informationUri": "https://github.com/gitleaks/gitleaks",
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": outcome.status == "completed",
                        "properties": {"error_code": outcome.error_code, "policy_result": outcome.policy_result},
                    }
                ],
                "properties": {"target": target_name, "scanner_version": outcome.scanner_version, "ruleset_digest": outcome.ruleset_digest},
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2) + "\n"


CSV_COLUMNS = [
    "fingerprint", "severity", "confidence", "rule_id", "title", "rule_family",
    "relative_path", "start_line", "commit_sha", "status", "blocking", "remediation_key",
]


def _csv_safe(value: object) -> str:
    text = "" if value is None else str(value)
    # Neutralise spreadsheet formula injection from attacker-controlled paths.
    if text and text[0] in "=+-@\t\r":
        text = "'" + text
    return text


def to_csv(outcome: ScanOutcome) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_COLUMNS)
    for f in outcome.findings:
        d = f.to_safe_dict()
        writer.writerow([_csv_safe(d[c]) for c in CSV_COLUMNS])
    return buf.getvalue()


def result_line(outcome: ScanOutcome) -> str:
    if outcome.status != "completed":
        return f"Result: ERROR - {FAILED_MESSAGE} [{outcome.error_code}] {safe_message(outcome.error_code)}"
    if outcome.policy_result == "fail":
        return (
            f"Result: FAIL - {outcome.blocking_findings} blocking finding(s) at or above '{outcome.fail_on}' "
            f"({outcome.total_findings} total, {outcome.suppressed_findings} suppressed)"
        )
    if outcome.total_findings == 0:
        return f"Result: PASS - {CLEAN_MESSAGE}"
    return (
        f"Result: PASS - no blocking findings at or above '{outcome.fail_on}' "
        f"({outcome.total_findings} non-blocking, {outcome.suppressed_findings} suppressed)"
    )


def to_text(outcome: ScanOutcome, target_name: str, verbose: bool = False) -> str:
    lines = []
    digest = (outcome.ruleset_digest or "")[:19]
    lines.append(
        f"SecretSentinel {outcome.secretsentinel_version or __version__} | gitleaks {outcome.scanner_version or 'n/a'} "
        f"| ruleset {outcome.ruleset_version or 'n/a'} ({digest})"
    )
    commit = (outcome.commit_sha or "")[:12] or "n/a"
    lines.append(f"Target: {target_name}  Mode: {outcome.mode}  Scope: {outcome.scope or 'n/a'}  Commit: {commit}")
    lines.append(result_line(outcome))
    if outcome.findings:
        lines.append("")
        lines.append(f"  {'SEVERITY':<9} {'CONF':<6} {'STATUS':<10} {'RULE':<36} LOCATION")
        for f in outcome.findings:
            loc = f"{f.relative_path}:{f.start_line}" if f.start_line else f.relative_path
            if f.commit_sha:
                loc += f" @ {f.commit_sha[:10]}"
            status = "BLOCKING" if f.blocking else f.status
            lines.append(f"  {_SEV_LABEL.get(f.severity, f.severity):<9} {f.confidence:<6} {status:<10} {f.rule_id:<36} {loc}")
        lines.append("")
        lines.append("  Secret values are never displayed. See remediation guidance with:")
        lines.append("    secretsentinel rules list   (or open the dashboard)")
        if verbose:
            seen = set()
            for f in outcome.findings:
                if f.remediation_key in seen:
                    continue
                seen.add(f.remediation_key)
                rem = get_remediation(f.remediation_key)
                lines.append("")
                lines.append(f"  [{f.remediation_key}] {rem.title}")
                for i, step in enumerate(rem.steps, 1):
                    lines.append(f"     {i}. {step}")
    for w in outcome.warnings:
        lines.append(f"  warning: {w}")
    lines.append("")
    lines.append(SCOPE_NOTE)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# GitHub Actions output
# ---------------------------------------------------------------------------

def _escape_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: str) -> str:
    return _escape_data(value).replace(":", "%3A").replace(",", "%2C")


def github_annotations(outcome: ScanOutcome) -> Iterable[str]:
    for f in outcome.findings:
        if f.status == "suppressed":
            continue
        level = "error" if f.blocking else "warning"
        props = [f"file={_escape_property(f.relative_path or '.')}"]
        if f.start_line:
            props.append(f"line={f.start_line}")
        props.append(f"title={_escape_property('SecretSentinel: ' + (f.title or f.rule_id))}")
        msg = f"{f.rule_id} ({f.severity}, confidence {f.confidence}). Value redacted. Rotate the credential if real."
        yield f"::{level} {','.join(props)}::{_escape_data(msg)}"


def _md_cell(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")


def github_step_summary(outcome: ScanOutcome, target_name: str) -> str:
    lines = ["## SecretSentinel security scan", ""]
    lines.append(f"**{_md_cell(result_line(outcome))}**")
    lines.append("")
    lines.append(
        f"Mode `{outcome.mode}` | scope `{_md_cell(outcome.scope)}` | gitleaks `{outcome.scanner_version}` | "
        f"ruleset `{outcome.ruleset_version}` | fail-on `{outcome.fail_on}`"
    )
    if outcome.findings:
        lines += ["", "| Severity | Rule | Location | Status |", "|---|---|---|---|"]
        for f in outcome.findings[:200]:
            status = "blocking" if f.blocking else f.status
            loc = f"{f.relative_path}:{f.start_line}"
            lines.append(f"| {f.severity} | {_md_cell(f.rule_id)} | {_md_cell(loc)} | {status} |")
        if len(outcome.findings) > 200:
            lines.append(f"| ... | {len(outcome.findings) - 200} more | | |")
    for w in outcome.warnings:
        lines.append(f"> warning: {_md_cell(w)}")
    lines += ["", "_Secret values are redacted and never written to logs or artifacts._", ""]
    return "\n".join(lines)
