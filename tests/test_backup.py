import json
import sys

import pytest

from bastion.backup import (
    MANIFEST_NAME,
    create_backup,
    find_restore_collisions,
    restore_backup,
    verify_backup,
)
from bastion.errors import BackupError, BastionError, PathValidationError
from bastion.fsutil import confirm_overwrite


@pytest.fixture
def source(make_files):
    d = make_files(4)
    (d / "sub").mkdir()
    (d / "sub" / "inner.txt").write_text("file in a subfolder")
    return d


def test_backup_verify_and_restore_roundtrip(source, tmp_path):
    result = create_backup(source, tmp_path / "vault")
    assert result.files == 5 and len(result.manifest_digest) == 64
    report = verify_backup(result.path)
    assert report.ok and report.checked == 5
    target = tmp_path / "restored"
    restored = restore_backup(result.path, target)
    assert restored.restored == 5
    for f in source.rglob("*.txt"):
        assert (target / f.relative_to(source)).read_bytes() == f.read_bytes()


def test_verify_detects_corruption_missing_and_extra(source, tmp_path):
    b = create_backup(source, tmp_path / "vault").path
    (b / "files" / "f00.txt").write_text("tampered")
    (b / "files" / "f01.txt").unlink()
    (b / "files" / "intruder.txt").write_text("not in the manifest")
    r = verify_backup(b)
    assert not r.ok
    assert r.corrupted == ["f00.txt"] and r.missing == ["f01.txt"] and r.unexpected == ["intruder.txt"]


def test_restore_refuses_corrupted_backup(source, tmp_path):
    b = create_backup(source, tmp_path / "vault").path
    (b / "files" / "f00.txt").write_text("tampered")
    target = tmp_path / "restored"
    with pytest.raises(BackupError, match="integrity check"):
        restore_backup(b, target)
    assert not target.exists()


def test_manifest_digest_detects_coordinated_tampering(source, tmp_path):
    result = create_backup(source, tmp_path / "vault")
    manifest = result.path / MANIFEST_NAME
    data = json.loads(manifest.read_text())
    data["files"][0]["sha256"] = "0" * 64   # manifest edit
    manifest.write_text(json.dumps(data))
    r = verify_backup(result.path, expected_digest=result.manifest_digest)
    assert not r.ok and r.digest_matches is False


def test_path_traversal_in_manifest_is_rejected(source, tmp_path):
    result = create_backup(source, tmp_path / "vault")
    manifest = result.path / MANIFEST_NAME
    data = json.loads(manifest.read_text())
    data["files"][0]["path"] = "../../escaped.txt"
    manifest.write_text(json.dumps(data))
    assert verify_backup(result.path).invalid_paths == ["../../escaped.txt"]
    with pytest.raises(BackupError):
        restore_backup(result.path, tmp_path / "target")
    assert not (tmp_path / "escaped.txt").exists()


def test_restore_never_overwrites_without_permission(source, tmp_path):
    b = create_backup(source, tmp_path / "vault").path
    target = tmp_path / "target"
    target.mkdir()
    (target / "f00.txt").write_text("user's version")
    assert find_restore_collisions(b, target) == [target / "f00.txt"]
    with pytest.raises(BackupError, match="would be replaced"):
        restore_backup(b, target)
    assert (target / "f00.txt").read_text() == "user's version"
    restore_backup(b, target, overwrite=True)
    assert (target / "f00.txt").read_text() == (source / "f00.txt").read_text()


def test_restoring_over_identical_files_is_not_a_collision(source, tmp_path):
    b = create_backup(source, tmp_path / "vault").path
    target = tmp_path / "target"
    restore_backup(b, target)
    again = restore_backup(b, target)
    assert again.restored == 0 and again.skipped_identical == 5
    (target / "f02.txt").unlink()  # a "lost" file comes back without needing overwrite
    assert restore_backup(b, target).restored == 1


def test_backup_never_overwrites_existing_backup(source, tmp_path):
    create_backup(source, tmp_path / "vault", name="b1")
    with pytest.raises(BackupError, match="never overwritten"):
        create_backup(source, tmp_path / "vault", name="b1")


def test_destination_inside_source_is_rejected(source):
    with pytest.raises(PathValidationError):
        create_backup(source, source / "backups")


def test_restore_into_backup_dir_is_rejected(source, tmp_path):
    b = create_backup(source, tmp_path / "vault").path
    with pytest.raises(PathValidationError):
        restore_backup(b, b / "files")


def test_invalid_backup_name(source, tmp_path):
    with pytest.raises(BackupError):
        create_backup(source, tmp_path / "vault", name="../escape")


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
def test_symlinks_are_not_followed(source, tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("must not enter the backup")
    (source / "shortcut.txt").symlink_to(outside)
    result = create_backup(source, tmp_path / "vault")
    assert any(s["path"] == "shortcut.txt" for s in result.skipped)
    assert not (result.path / "files" / "shortcut.txt").exists()


def test_same_device_warning_is_present(source, tmp_path):
    result = create_backup(source, tmp_path / "vault")
    assert any("SAME drive" in w for w in result.warnings)


# --- overwrite confirmation (used by the CLI) --------------------------------------

def test_confirm_overwrite_rules(tmp_path):
    c = [tmp_path / "a.txt"]
    confirm_overwrite([], allow_overwrite=False, assume_yes=False)
    with pytest.raises(BastionError, match="were NOT changed"):
        confirm_overwrite(c, allow_overwrite=False, assume_yes=False)
    with pytest.raises(BastionError, match="no interactive terminal"):
        confirm_overwrite(c, allow_overwrite=True, assume_yes=False, is_tty=False)
    confirm_overwrite(c, allow_overwrite=True, assume_yes=True)
    confirm_overwrite(c, allow_overwrite=True, assume_yes=False, is_tty=True, input_fn=lambda _p: "yes")
    with pytest.raises(BastionError, match="cancelled"):
        confirm_overwrite(c, allow_overwrite=True, assume_yes=False, is_tty=True, input_fn=lambda _p: "no")
