"""Release and reuse files: the PyPI release workflow, the reusable GitHub
Action (action.yml) and the build hook that ships the ruleset in the wheel.

These are checked statically here; scripts/check_package.sh (CI "package" job)
checks a real wheel, and the action steps were exercised with a local runner.
"""

import ast
import re
from pathlib import Path

import yaml

from secretsentinel.cli import build_parser
from secretsentinel.services.rules import MAPPING_FILE, WEB3_RULES_FILE

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
PINNED = re.compile(r"^[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}$")


def _yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _steps(doc: dict):
    if "runs" in doc:  # action.yml
        yield from doc["runs"]["steps"]
    for job in (doc.get("jobs") or {}).values():
        yield from job.get("steps", [])


def _gitleaks_pins(text: str) -> tuple[str, str]:
    version = re.search(r'GITLEAKS_VERSION: "([^"]+)"', text).group(1)
    sha = re.search(r'GITLEAKS_SHA256: "([0-9a-f]{64})"', text).group(1)
    return version, sha


def test_every_action_reference_is_pinned_to_a_commit():
    files = [ROOT / "action.yml", *sorted(WORKFLOWS.glob("*.yml"))]
    for path in files:
        for step in _steps(_yaml(path)):
            if "uses" in step and not step["uses"].startswith("./"):
                assert PINNED.match(step["uses"]), f"{path.name}: {step['uses']} is not pinned to a commit SHA"


def test_gitleaks_pin_is_the_same_everywhere():
    reference = _gitleaks_pins((WORKFLOWS / "secret-scan.yml").read_text(encoding="utf-8"))
    for path in (ROOT / "action.yml", WORKFLOWS / "release.yml", WORKFLOWS / "backend-tests.yml"):
        assert _gitleaks_pins(path.read_text(encoding="utf-8")) == reference, path.name


def test_action_is_composite_and_inputs_cannot_inject_shell():
    action = _yaml(ROOT / "action.yml")
    assert action["runs"]["using"] == "composite"
    assert set(action["inputs"]) == {"path", "mode", "fail-on", "policy"}
    for step in action["runs"]["steps"]:
        # Inputs reach scripts only through env; a ${{ }} inside run: would be pasted into bash.
        assert "${{" not in step.get("run", ""), step.get("name")
    setup = next(s for s in action["runs"]["steps"] if s.get("uses", "").startswith("actions/setup-python@"))
    assert setup["with"]["update-environment"] is False  # leave the caller's Python alone


def test_cli_accepts_the_arguments_the_action_builds():
    args = build_parser().parse_args([
        "check", ".", "--mode", "both", "--github-annotations", "--github-summary", "--no-size-limit",
        "--fail-on", "high", "--policy", "policy.yml",
    ])
    assert (args.mode, args.fail_on, args.policy) == ("both", "high", "policy.yml")


def test_release_publishes_only_from_version_tags_with_a_scoped_token():
    release = _yaml(WORKFLOWS / "release.yml")
    on = release[True]  # YAML 1.1 reads the key "on" as True
    assert set(on) == {"push"} and on["push"] == {"tags": ["v[0-9]+.[0-9]+.[0-9]+"]}
    assert release["permissions"] == {"contents": "read"}
    build, publish = release["jobs"]["build"], release["jobs"]["publish"]
    assert "permissions" not in build  # the build never sees the OIDC token
    assert publish["permissions"] == {"id-token": "write"}
    assert publish["environment"]["name"] == "pypi"
    assert publish["needs"] == "build"
    build_text = yaml.safe_dump(build)
    assert "Tag must match the package version" in build_text
    assert "scripts/check_package.sh" in build_text


def test_build_hook_ships_exactly_the_files_the_ruleset_reads():
    tree = ast.parse((ROOT / "backend" / "hatch_build.py").read_text(encoding="utf-8"))
    shipped = next(
        ast.literal_eval(node.value) for node in tree.body
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "RULE_FILES"
    )
    assert set(shipped) == {WEB3_RULES_FILE, MAPPING_FILE}
    pyproject = (ROOT / "backend" / "pyproject.toml").read_text(encoding="utf-8")
    assert "[tool.hatch.build.hooks.custom]" in pyproject
    assert 'name = "secretsentinel-scanner"' in pyproject
