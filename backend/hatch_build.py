"""Hatch build hook: ship the detection ruleset inside the package.

The canonical rules live in ``rules/`` at the repository root, next to
``backend/``. Without this hook an installed package has no ruleset and the CLI
stops with "rules directory not found". The sdist carries a copy at ``rules/``;
the wheel (built from a checkout or from the sdist) gets it at
``secretsentinel/rules/``, which ``secretsentinel.paths.find_rules_dir`` finds
first because it starts searching in the package directory.

Only the two files the scanner reads are shipped. Test fixtures are not.
"""

from __future__ import annotations

from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

RULE_FILES = ("web3_rules.toml", "severity_mapping.yaml")


class RulesBuildHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        root = Path(self.root)
        # An sdist has rules/ inside it; a source checkout has it one level up.
        for source in (root / "rules", root.parent / "rules"):
            if all((source / name).is_file() for name in RULE_FILES):
                break
        else:
            raise RuntimeError("SecretSentinel rules not found: build from a source checkout or from the sdist")
        prefix = "secretsentinel/rules" if self.target_name == "wheel" else "rules"
        for name in RULE_FILES:
            build_data["force_include"][str(source / name)] = f"{prefix}/{name}"
