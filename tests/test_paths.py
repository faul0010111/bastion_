import sys

import pytest

from bastion.errors import PathValidationError
from bastion.paths import (
    ensure_disjoint,
    is_ignored,
    is_within,
    resolve_existing_dir,
    resolve_existing_file,
    safe_relative_join,
    to_relative_posix,
)


def test_resolve_existing_dir_errors(tmp_path):
    assert resolve_existing_dir(tmp_path) == tmp_path.resolve()
    with pytest.raises(PathValidationError, match="not found"):
        resolve_existing_dir(tmp_path / "does_not_exist")
    f = tmp_path / "a.txt"
    f.write_text("x")
    with pytest.raises(PathValidationError, match="not a folder"):
        resolve_existing_dir(f)
    for bad in ("", "   ", "a\x00b"):
        with pytest.raises(PathValidationError):
            resolve_existing_dir(bad)


def test_filesystem_root_is_refused():
    root = "C:\\" if sys.platform == "win32" else "/"
    with pytest.raises(PathValidationError, match="root"):
        resolve_existing_dir(root)


def test_resolve_existing_file_rejects_directories(tmp_path):
    with pytest.raises(PathValidationError, match="folder"):
        resolve_existing_file(tmp_path)
    with pytest.raises(PathValidationError, match="not found"):
        resolve_existing_file(tmp_path / "x")


def test_is_within_and_disjoint(tmp_path):
    a, b = tmp_path / "a", tmp_path / "a" / "b"
    b.mkdir(parents=True)
    assert is_within(b, a) and is_within(a, a) and not is_within(a, b)
    with pytest.raises(PathValidationError):
        ensure_disjoint(a, b, label_a="A", label_b="B")
    other = tmp_path / "c"
    other.mkdir()
    ensure_disjoint(a, other, label_a="A", label_b="C")


@pytest.mark.parametrize("rel", ["../x", "a/../../x", "/etc/passwd", "", ".", "a\x00b"])
def test_safe_relative_join_blocks_escape(tmp_path, rel):
    with pytest.raises(PathValidationError):
        safe_relative_join(tmp_path, rel)


def test_safe_relative_join_allows_normal_paths(tmp_path):
    assert safe_relative_join(tmp_path, "a/b/c.txt") == tmp_path / "a" / "b" / "c.txt"


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
def test_safe_relative_join_blocks_symlink_escape(tmp_path):
    base, outside = tmp_path / "base", tmp_path / "outside"
    base.mkdir()
    outside.mkdir()
    (base / "shortcut").symlink_to(outside)
    with pytest.raises(PathValidationError):
        safe_relative_join(base, "shortcut/file.txt")


def test_relative_posix_and_ignore(tmp_path):
    assert to_relative_posix(tmp_path / "a" / "b.txt", tmp_path) == "a/b.txt"
    assert to_relative_posix("/somewhere/else", tmp_path) is None
    assert is_ignored("a/b/file.swp", ["*.swp"]) and is_ignored("x/~$doc.docx", ["~$*"])
    assert not is_ignored("a/b.txt", ["*.swp"])
