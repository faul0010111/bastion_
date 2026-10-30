"""Verifiable file inventory: scanning, root hash and comparison.

The inventory stores, per file, SHA-256, size, mtime and entropy. The *root
hash* summarizes the whole set: if you write it down off the machine, any later
tampering with the inventory becomes detectable.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from .errors import InventoryError
from .events import Event
from .fingerprint import fingerprint_file
from .fsutil import atomic_write_json
from .paths import is_ignored

FORMAT_VERSION = 1


@dataclass(frozen=True)
class FileEntry:
    path: str
    size: int
    mtime_ns: int
    sha256: str
    entropy: float
    magic: str = ""


@dataclass
class Inventory:
    root: str
    created_at: float
    entries: Dict[str, FileEntry] = field(default_factory=dict)
    skipped: List[Dict[str, str]] = field(default_factory=list)

    def root_hash(self) -> str:
        """Hash summarizing every path and content (independent of order)."""
        digest = hashlib.sha256()
        for path in sorted(self.entries):
            line = json.dumps([path, self.entries[path].sha256], ensure_ascii=False)
            digest.update(line.encode("utf-8") + b"\n")
        return digest.hexdigest()

    def to_dict(self) -> dict:
        return {
            "format": FORMAT_VERSION,
            "root": self.root,
            "created_at": self.created_at,
            "root_hash": self.root_hash(),
            "files": [
                {"path": e.path, "size": e.size, "mtime_ns": e.mtime_ns,
                 "sha256": e.sha256, "entropy": e.entropy, "magic": e.magic}
                for _, e in sorted(self.entries.items())
            ],
            "skipped": self.skipped,
        }


def scan_directory(
    root: Path,
    ignore: Sequence[str] = (),
    progress: Optional[Callable[[int], None]] = None,
) -> Inventory:
    """Walk ``root`` without following links and without stopping on isolated errors."""
    inv = Inventory(root=str(root), created_at=time.time())
    count = 0

    def on_walk_error(exc: OSError) -> None:
        where = str(exc.filename or root)
        inv.skipped.append({"path": where, "reason": f"unreadable folder: {exc.strerror or exc}"})

    for dirpath, dirnames, filenames in os.walk(root, onerror=on_walk_error, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = Path(full).relative_to(root).as_posix()
            if is_ignored(rel, ignore):
                continue
            try:
                st = os.lstat(full)
            except OSError as exc:
                inv.skipped.append({"path": rel, "reason": f"could not stat: {exc.strerror or exc}"})
                continue
            if not stat.S_ISREG(st.st_mode):
                inv.skipped.append({"path": rel, "reason": "symbolic link or special file (ignored)"})
                continue
            try:
                fp = fingerprint_file(full)
            except FileNotFoundError:
                inv.skipped.append({"path": rel, "reason": "removed during scan"})
                continue
            except PermissionError:
                inv.skipped.append({"path": rel, "reason": "no read permission"})
                continue
            except OSError as exc:
                inv.skipped.append({"path": rel, "reason": f"read error: {exc.strerror or exc}"})
                continue
            inv.entries[rel] = FileEntry(rel, fp.size, st.st_mtime_ns, fp.sha256, fp.entropy, fp.magic)
            count += 1
            if progress and count % 200 == 0:
                progress(count)
    return inv


def save_inventory(inv: Inventory, path: Path) -> None:
    atomic_write_json(path, inv.to_dict())


def load_inventory(path: Path) -> Inventory:
    """Load and check the stored root hash: detects corruption or manual edits."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data.get("format") != FORMAT_VERSION:
            raise InventoryError(f"Unsupported inventory format in {path}.")
        inv = Inventory(root=data["root"], created_at=float(data["created_at"]))
        for item in data["files"]:
            inv.entries[item["path"]] = FileEntry(
                item["path"], int(item["size"]), int(item["mtime_ns"]),
                str(item["sha256"]), float(item["entropy"]), str(item.get("magic", "")),
            )
        inv.skipped = list(data.get("skipped", []))
        stored = data["root_hash"]
    except InventoryError:
        raise
    except FileNotFoundError:
        raise InventoryError(f"Inventory not found: {path}") from None
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise InventoryError(f"Inventory unreadable or corrupted ({path}): {exc}") from None
    if inv.root_hash() != stored:
        raise InventoryError(
            f"The root hash of {path} does not match: the inventory was altered or is corrupted. "
            "Do not trust it for comparisons; compare against the root hash you wrote down."
        )
    return inv


@dataclass
class InventoryDiff:
    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    modified: List[str] = field(default_factory=list)
    renamed: List[Tuple[str, str]] = field(default_factory=list)          # same content
    renamed_changed: List[Tuple[str, str]] = field(default_factory=list)  # similar name, new content
    unchanged: int = 0

    @property
    def total_changes(self) -> int:
        return (len(self.added) + len(self.removed) + len(self.modified)
                + len(self.renamed) + len(self.renamed_changed))

    @property
    def is_clean(self) -> bool:
        return self.total_changes == 0


def _name_key(path: str) -> Tuple[str, str]:
    p = PurePosixPath(path)
    return (p.parent.as_posix(), p.name.split(".")[0] or p.name)


def compare_inventories(old: Inventory, new: Inventory) -> InventoryDiff:
    old_paths, new_paths = set(old.entries), set(new.entries)
    removed = sorted(old_paths - new_paths)
    added = sorted(new_paths - old_paths)
    common = old_paths & new_paths
    diff = InventoryDiff()
    diff.modified = sorted(p for p in common if old.entries[p].sha256 != new.entries[p].sha256)
    diff.unchanged = len(common) - len(diff.modified)

    # "Pure" rename: same content, new path (pairing groups of equal size).
    rem_by_hash: Dict[str, List[str]] = defaultdict(list)
    add_by_hash: Dict[str, List[str]] = defaultdict(list)
    for p in removed:
        rem_by_hash[old.entries[p].sha256].append(p)
    for p in added:
        add_by_hash[new.entries[p].sha256].append(p)
    used_rem, used_add = set(), set()
    for sha, rems in rem_by_hash.items():
        adds = add_by_hash.get(sha, [])
        if rems and len(rems) == len(adds):
            for r, a in zip(sorted(rems), sorted(adds), strict=True):
                diff.renamed.append((r, a))
                used_rem.add(r)
                used_add.add(a)
    diff.renamed.sort()

    # Rename with changed content (e.g. report.docx -> report.docx.locked).
    rem_left = [p for p in removed if p not in used_rem]
    add_left = [p for p in added if p not in used_add]
    rem_keys: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    add_keys: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for p in rem_left:
        rem_keys[_name_key(p)].append(p)
    for p in add_left:
        add_keys[_name_key(p)].append(p)
    for key, rems in rem_keys.items():
        adds = add_keys.get(key, [])
        if len(rems) == 1 and len(adds) == 1:
            diff.renamed_changed.append((rems[0], adds[0]))
            used_rem.add(rems[0])
            used_add.add(adds[0])
    diff.renamed_changed.sort()

    diff.removed = [p for p in removed if p not in used_rem]
    diff.added = [p for p in added if p not in used_add]
    return diff


def diff_to_events(old: Inventory, new: Inventory, diff: InventoryDiff, now: float) -> List[Event]:
    """Turn the diff into events so the same rule engine can be reused."""
    events: List[Event] = []
    for p in diff.modified:
        n, o = new.entries[p], old.entries[p]
        events.append(Event("modified", p, now, sha256=n.sha256, size=n.size,
                            entropy=n.entropy, prev_entropy=o.entropy, magic=n.magic,
                            prev_magic=o.magic, source="verify"))
    for src, dst in diff.renamed + diff.renamed_changed:
        n, o = new.entries[dst], old.entries[src]
        events.append(Event("moved", src, now, dest_path=dst, sha256=n.sha256, size=n.size,
                            entropy=n.entropy, prev_entropy=o.entropy, magic=n.magic,
                            prev_magic=o.magic, source="verify"))
    for p in diff.added:
        n = new.entries[p]
        events.append(Event("created", p, now, sha256=n.sha256, size=n.size,
                            entropy=n.entropy, magic=n.magic, source="verify"))
    for p in diff.removed:
        events.append(Event("deleted", p, now, source="verify"))
    return events
