"""The central scanner's repository list must only ever yield safe names."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("fleet_matrix", ROOT / "scripts" / "fleet_matrix.py")
fleet_matrix = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fleet_matrix)


def test_parses_comments_blanks_and_duplicates():
    text = "# header\n\nowner/repo-a\n  Owner/Repo-A  # same, different case\nother/b.c_d  # trailing\n"
    assert fleet_matrix.parse(text) == ["owner/repo-a", "other/b.c_d"]


@pytest.mark.parametrize(
    "line",
    [
        "no-slash",
        "a/b/c",
        "owner/..",
        "owner/.",
        "owner/re po",
        "owner/$(id)",
        "owner/repo;rm",
        "-owner/repo",
        "https://github.com/owner/repo",
        'owner/"repo"',
    ],
)
def test_rejects_unsafe_entries(line):
    with pytest.raises(ValueError):
        fleet_matrix.parse(line)


def test_rejects_oversized_list():
    text = "\n".join(f"o/r{i}" for i in range(fleet_matrix.MAX_REPOS + 1))
    with pytest.raises(ValueError):
        fleet_matrix.parse(text)


def test_repository_list_in_repo_is_valid(capsys):
    assert fleet_matrix.main([str(ROOT / ".github" / "dashboard-repos.txt")]) == 0
    repos = json.loads(capsys.readouterr().out)
    assert repos and all("/" in r for r in repos)
