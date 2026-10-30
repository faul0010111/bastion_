import json
import os
import sys

import pytest

from bastion import inventory as inv_mod
from bastion.errors import InventoryError
from bastion.inventory import (
    compare_inventories,
    diff_to_events,
    load_inventory,
    save_inventory,
    scan_directory,
)


def test_scan_records_hash_size_entropy(make_files):
    d = make_files(3)
    inv = scan_directory(d)
    assert set(inv.entries) == {"f00.txt", "f01.txt", "f02.txt"}
    e = inv.entries["f00.txt"]
    assert len(e.sha256) == 64 and e.size > 0 and 0 < e.entropy < 6


def test_root_hash_is_deterministic_and_content_sensitive(make_files):
    d = make_files(3)
    a, b = scan_directory(d), scan_directory(d)
    assert a.root_hash() == b.root_hash()
    (d / "f01.txt").write_text("changed")
    assert scan_directory(d).root_hash() != a.root_hash()


def test_save_load_roundtrip_and_tamper_detection(make_files, tmp_path):
    d = make_files(3)
    path = tmp_path / "state" / "inv.json"
    inv = scan_directory(d)
    save_inventory(inv, path)
    assert load_inventory(path).root_hash() == inv.root_hash()
    # manual edit: swap one hash without recomputing the root hash
    data = json.loads(path.read_text())
    data["files"][0]["sha256"] = "0" * 64
    path.write_text(json.dumps(data))
    with pytest.raises(InventoryError, match="root hash"):
        load_inventory(path)
    path.write_text("garbage")
    with pytest.raises(InventoryError):
        load_inventory(path)
    with pytest.raises(InventoryError):
        load_inventory(tmp_path / "missing.json")


def test_diff_detects_every_kind_of_change(make_files):
    d = make_files(6)
    old = scan_directory(d)
    (d / "f00.txt").write_text("new and different content")             # modified
    (d / "f01.txt").rename(d / "renamed.txt")                           # renamed, same content
    (d / "f02.txt").write_text("changed as well")
    (d / "f02.txt").rename(d / "f02.txt.locked")                        # renamed + different content
    (d / "f03.txt").unlink()                                            # removed
    (d / "new.txt").write_text("a new file")                            # added
    new = scan_directory(d)
    diff = compare_inventories(old, new)
    assert diff.modified == ["f00.txt"]
    assert diff.renamed == [("f01.txt", "renamed.txt")]
    assert diff.renamed_changed == [("f02.txt", "f02.txt.locked")]
    assert diff.removed == ["f03.txt"]
    assert diff.added == ["new.txt"]
    assert diff.unchanged == 2 and not diff.is_clean


def test_clean_diff(make_files):
    d = make_files(3)
    inv = scan_directory(d)
    assert compare_inventories(inv, scan_directory(d)).is_clean


def test_diff_to_events_carry_previous_entropy(make_files):
    d = make_files(2)
    old = scan_directory(d)
    (d / "f00.txt").write_bytes(os.urandom(4096))
    new = scan_directory(d)
    events = diff_to_events(old, new, compare_inventories(old, new), now=100.0)
    assert len(events) == 1
    e = events[0]
    assert e.type == "modified" and e.prev_entropy < 6 and e.entropy > 7.5 and e.ts == 100.0


def test_ignore_patterns(make_files):
    d = make_files(2)
    (d / "draft.tmp").write_text("x")
    (d / "~$doc.docx").write_text("x")
    inv = scan_directory(d, ["*.tmp", "~$*"])
    assert "draft.tmp" not in inv.entries and "~$doc.docx" not in inv.entries


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinks_are_skipped_not_followed(make_files, tmp_path):
    d = make_files(1)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    (d / "link.txt").symlink_to(outside)
    inv = scan_directory(d)
    assert "link.txt" not in inv.entries
    assert any(s["path"] == "link.txt" for s in inv.skipped)


@pytest.mark.skipif(sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="permissions do not apply to root/Windows")
def test_unreadable_file_is_reported_and_scan_continues(make_files):
    d = make_files(2)
    locked = d / "f00.txt"
    locked.chmod(0)
    try:
        inv = scan_directory(d)
    finally:
        locked.chmod(0o600)
    assert "f01.txt" in inv.entries and "f00.txt" not in inv.entries
    assert any("permission" in s["reason"] for s in inv.skipped)


def test_file_removed_during_scan_is_handled(make_files, monkeypatch):
    d = make_files(3)
    real = inv_mod.fingerprint_file

    def flaky(path):
        if str(path).endswith("f01.txt"):
            raise FileNotFoundError(path)
        return real(path)

    monkeypatch.setattr(inv_mod, "fingerprint_file", flaky)
    inv = scan_directory(d)
    assert set(inv.entries) == {"f00.txt", "f02.txt"}
    assert any("removed during scan" in s["reason"] for s in inv.skipped)
