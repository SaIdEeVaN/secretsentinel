"""Path allowlisting, symlink escapes, Git ref validation and globs (T14)."""

import os

import pytest

from secretsentinel.core.errors import ErrorCode, SecretSentinelError
from secretsentinel.core.security import (
    canonicalize_existing_dir,
    check_repo_size,
    ensure_within_allowed_roots,
    glob_match,
    glob_to_regex,
    safe_text,
    validate_ref_syntax,
)


def test_canonicalize_rejects_missing_and_files(tmp_path):
    with pytest.raises(SecretSentinelError) as e:
        canonicalize_existing_dir(tmp_path / "nope")
    assert e.value.code == ErrorCode.PATH_NOT_FOUND
    f = tmp_path / "file.txt"
    f.write_text("x")
    with pytest.raises(SecretSentinelError):
        canonicalize_existing_dir(f)
    with pytest.raises(SecretSentinelError):
        canonicalize_existing_dir("bad\x00path")


def test_out_of_root_path_rejected_T14(tmp_path):
    root = tmp_path / "root"
    (root / "repo").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    assert ensure_within_allowed_roots(canonicalize_existing_dir(root / "repo"), [root])
    with pytest.raises(SecretSentinelError) as e:
        ensure_within_allowed_roots(canonicalize_existing_dir(outside), [root])
    assert e.value.code == ErrorCode.PATH_NOT_ALLOWED
    with pytest.raises(SecretSentinelError):
        ensure_within_allowed_roots(canonicalize_existing_dir(root / "repo" / ".." / ".."), [root])
    with pytest.raises(SecretSentinelError):
        ensure_within_allowed_roots(canonicalize_existing_dir(outside), [])


def test_prefix_sibling_is_not_inside_root(tmp_path):
    (tmp_path / "root").mkdir()
    (tmp_path / "root-evil").mkdir()
    with pytest.raises(SecretSentinelError):
        ensure_within_allowed_roots(canonicalize_existing_dir(tmp_path / "root-evil"), [tmp_path / "root"])


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_symlink_escape_rejected(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    secret_dir = tmp_path / "private"
    secret_dir.mkdir()
    (root / "link").symlink_to(secret_dir, target_is_directory=True)
    with pytest.raises(SecretSentinelError) as e:
        ensure_within_allowed_roots(canonicalize_existing_dir(root / "link"), [root])
    assert e.value.code == ErrorCode.PATH_NOT_ALLOWED


def test_repo_size_limit(tmp_path):
    (tmp_path / "big.bin").write_bytes(b"\0" * (2 * 1024 * 1024))
    assert check_repo_size(tmp_path, max_mb=5, max_files=100) >= 2 * 1024 * 1024
    with pytest.raises(SecretSentinelError) as e:
        check_repo_size(tmp_path, max_mb=1, max_files=100)
    assert e.value.code == ErrorCode.REPO_TOO_LARGE
    for i in range(5):
        (tmp_path / f"f{i}").write_text("x")
    with pytest.raises(SecretSentinelError):
        check_repo_size(tmp_path, max_mb=100, max_files=3)


@pytest.mark.parametrize("ref", ["main", "origin/main", "v1.2.3", "a" * 40, "HEAD~3", "feature/x-y_z"])
def test_valid_refs(ref):
    assert validate_ref_syntax(ref) == ref


@pytest.mark.parametrize(
    "ref",
    ["", "-x", "--output=/tmp/x", "main..HEAD", "a b", "a\nb", "refs//x", "x/", "x.lock", "$(id)", "a;b", "x" * 300],
)
def test_invalid_refs(ref):
    with pytest.raises(SecretSentinelError) as e:
        validate_ref_syntax(ref)
    assert e.value.code == ErrorCode.INVALID_GIT_REF


@pytest.mark.parametrize(
    "pattern,path,desc,expected",
    [
        ("node_modules", "node_modules/a.js", True, True),
        ("node_modules", "pkg/node_modules/a.js", True, True),
        ("node_modules", "node_modules_x/a.js", True, False),
        ("**/tests/**", "backend/tests/x.py", False, True),
        ("**/*.md", "README.md", False, True),
        ("rules/fixtures/**", "rules/fixtures/a/b", False, True),
        ("rules/fixtures/**", "x/rules/fixtures/a", False, False),
        ("dist/", "dist/app.js", True, True),
        ("*.min.js", "web/app.min.js", False, True),
        ("src/[weird].py", "src/[weird].py", False, True),
    ],
)
def test_glob_semantics(pattern, path, desc, expected):
    assert glob_match(pattern, path, descendants=desc) is expected


def test_glob_regex_is_go_compatible():
    rx = glob_to_regex("a b/**/c?.txt", descendants=True)
    for token in ("(?=", "(?!", "(?<=", "(?<!", "\\ "):
        assert token not in rx


def test_safe_text_strips_control_characters():
    assert safe_text("a\x1b[2Jb\nc", 100) == "a?[2Jb?c"
    assert len(safe_text("x" * 1000, 20)) == 20
