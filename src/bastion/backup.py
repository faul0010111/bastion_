"""Demo backup with manifest, validation and safe restore.

Layout of a backup::

    <destination>/<name>/
        manifest.json      # paths, sizes, SHA-256 and root hash
        files/...          # copy of the files

The *manifest digest* is printed at creation time. Write it down off the
machine: whoever alters files and manifest together cannot reproduce it.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .errors import BackupError, PathValidationError
from .fingerprint import CHUNK_SIZE
from .fsutil import atomic_copy
from .paths import ensure_disjoint, is_ignored, resolve_existing_dir, resolve_path, safe_relative_join

MANIFEST_NAME = "manifest.json"
FILES_DIR = "files"
FORMAT_VERSION = 1


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _root_hash(files: Sequence[dict]) -> str:
    digest = hashlib.sha256()
    for item in sorted(files, key=lambda f: f["path"]):
        digest.update(json.dumps([item["path"], item["sha256"]], ensure_ascii=False).encode("utf-8") + b"\n")
    return digest.hexdigest()


@dataclass
class BackupResult:
    path: Path
    files: int
    total_bytes: int
    root_hash: str
    manifest_digest: str
    skipped: List[Dict[str, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def create_backup(
    source: Path,
    dest_base: Path,
    *,
    name: Optional[str] = None,
    ignore: Sequence[str] = (),
) -> BackupResult:
    source = resolve_existing_dir(source, label="backup source")
    dest_base = resolve_path(dest_base)
    ensure_disjoint(source, dest_base, label_a="The source", label_b="the backup destination")
    name = name or "backup-" + datetime.now().strftime("%Y%m%d-%H%M%S")
    if not name or "/" in name or "\\" in name or name in (".", "..") or "\x00" in name:
        raise BackupError(f"Invalid backup name: {name!r}")
    final = dest_base / name
    if final.exists():
        raise BackupError(f"'{final}' already exists. Backups are never overwritten; choose another name.")
    dest_base.mkdir(parents=True, exist_ok=True)
    tmp = dest_base / f".{name}.partial"
    if tmp.exists():
        raise BackupError(f"A leftover partial copy exists at '{tmp}'. Remove it manually and try again.")

    warnings: List[str] = []
    try:
        if os.stat(source).st_dev == os.stat(dest_base).st_dev:
            warnings.append(
                "The destination is on the SAME drive as the source. A backup only protects you if it "
                "lives on separate media or in a separate location (ideally an offline/immutable copy)."
            )
    except OSError:
        pass

    entries: List[dict] = []
    skipped: List[Dict[str, str]] = []
    total = 0
    (tmp / FILES_DIR).mkdir(parents=True)
    try:
        for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
            dirnames.sort()
            for fname in sorted(filenames):
                full = Path(dirpath) / fname
                rel = full.relative_to(source).as_posix()
                if is_ignored(rel, ignore):
                    continue
                try:
                    st = os.lstat(full)
                    if not stat.S_ISREG(st.st_mode):
                        skipped.append({"path": rel, "reason": "symbolic link or special file"})
                        continue
                    out = tmp / FILES_DIR / rel
                    out.parent.mkdir(parents=True, exist_ok=True)
                    atomic_copy(full, out)
                    entries.append({"path": rel, "size": out.stat().st_size,
                                    "sha256": _sha256_file(out), "mtime_ns": st.st_mtime_ns})
                    total += entries[-1]["size"]
                except FileNotFoundError:
                    skipped.append({"path": rel, "reason": "removed during backup"})
                except PermissionError:
                    skipped.append({"path": rel, "reason": "no read permission"})
                except OSError as exc:
                    skipped.append({"path": rel, "reason": f"error: {exc.strerror or exc}"})
        if not entries:
            raise BackupError("No copyable files found in the source.")
        manifest = {
            "format": FORMAT_VERSION, "name": name, "tool_version": __version__,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source": str(source), "root_hash": _root_hash(entries),
            "files": sorted(entries, key=lambda f: f["path"]),
        }
        text = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        payload = text.encode("utf-8")
        # write_bytes: text mode would turn "\n" into "\r\n" on Windows and break the digest.
        (tmp / MANIFEST_NAME).write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        os.replace(tmp, final)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return BackupResult(final, len(entries), total, str(manifest["root_hash"]), digest, skipped, warnings)


def load_manifest(backup_dir: Path) -> Dict[str, Any]:
    path = Path(backup_dir) / MANIFEST_NAME
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
        if data["format"] != FORMAT_VERSION:
            raise BackupError("Unsupported backup format.")
        for item in data["files"]:
            if not (isinstance(item["path"], str) and isinstance(item["sha256"], str)
                    and isinstance(item["size"], int)):
                raise ValueError("malformed file entry")
        data["_digest"] = hashlib.sha256(raw).hexdigest()
        manifest: Dict[str, Any] = data
        return manifest
    except BackupError:
        raise
    except FileNotFoundError:
        raise BackupError(f"Invalid backup: '{MANIFEST_NAME}' not found in {backup_dir}.") from None
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise BackupError(f"Manifest unreadable or corrupted: {exc}") from None


@dataclass
class VerifyReport:
    checked: int = 0
    missing: List[str] = field(default_factory=list)
    corrupted: List[str] = field(default_factory=list)
    unexpected: List[str] = field(default_factory=list)
    invalid_paths: List[str] = field(default_factory=list)
    manifest_ok: bool = True
    digest: str = ""
    digest_matches: Optional[bool] = None

    @property
    def ok(self) -> bool:
        return (self.manifest_ok and not (self.missing or self.corrupted or self.unexpected or self.invalid_paths)
                and self.digest_matches is not False)


def verify_backup(backup_dir: Path, expected_digest: Optional[str] = None) -> VerifyReport:
    backup_dir = Path(backup_dir)
    manifest = load_manifest(backup_dir)
    report = VerifyReport(digest=manifest["_digest"])
    if expected_digest is not None:
        report.digest_matches = expected_digest.strip().lower() == report.digest
    if _root_hash(manifest["files"]) != manifest.get("root_hash"):
        report.manifest_ok = False
    base = backup_dir / FILES_DIR
    known = set()
    for item in manifest["files"]:
        rel = item["path"]
        try:
            target = safe_relative_join(base, rel)
        except PathValidationError:
            report.invalid_paths.append(rel)
            continue
        known.add(rel)
        report.checked += 1
        if not target.is_file():
            report.missing.append(rel)
            continue
        try:
            if _sha256_file(target) != item["sha256"]:
                report.corrupted.append(rel)
        except OSError:
            report.corrupted.append(rel)
    if base.is_dir():
        for dirpath, _d, filenames in os.walk(base):
            for fname in filenames:
                rel = (Path(dirpath) / fname).relative_to(base).as_posix()
                if rel not in known:
                    report.unexpected.append(rel)
    return report


def find_restore_collisions(backup_dir: Path, target: Path) -> List[Path]:
    """Files that already exist at the destination WITH content different from the backup."""
    manifest = load_manifest(backup_dir)
    target = resolve_path(target)
    out: List[Path] = []
    for item in manifest["files"]:
        dst = safe_relative_join(target, item["path"])
        if dst.exists() or dst.is_symlink():
            try:
                same = dst.is_file() and not dst.is_symlink() and _sha256_file(dst) == item["sha256"]
            except OSError:
                same = False
            if not same:
                out.append(dst)
    return out


@dataclass
class RestoreResult:
    restored: int
    skipped_identical: int
    target: Path


def restore_backup(backup_dir: Path, target: Path, *, overwrite: bool = False) -> RestoreResult:
    """Restore a VALID backup. Different files are only replaced if ``overwrite`` is True
    (asking the user for confirmation is the caller's responsibility)."""
    backup_dir = Path(backup_dir).resolve()
    report = verify_backup(backup_dir)
    if not report.ok:
        raise BackupError(
            "The backup failed the integrity check; the restore was cancelled "
            f"(missing: {len(report.missing)}, corrupted: {len(report.corrupted)}, "
            f"unexpected: {len(report.unexpected)}, invalid paths: {len(report.invalid_paths)})."
        )
    target = resolve_path(target)
    ensure_disjoint(backup_dir, target, label_a="The backup", label_b="the restore destination")
    if target.exists() and not target.is_dir():
        raise BackupError(f"The destination exists and is not a folder: {target}")
    collisions = find_restore_collisions(backup_dir, target)
    if collisions and not overwrite:
        raise BackupError(f"{len(collisions)} file(s) at the destination would be replaced; nothing was changed.")
    manifest = load_manifest(backup_dir)
    restored = identical = 0
    for item in manifest["files"]:
        src = safe_relative_join(backup_dir / FILES_DIR, item["path"])
        dst = safe_relative_join(target, item["path"])
        if dst.is_file() and not dst.is_symlink() and dst not in collisions:
            identical += 1
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        atomic_copy(src, dst)
        if _sha256_file(dst) != item["sha256"]:
            raise BackupError(f"Post-copy verification failed for '{item['path']}'.")
        restored += 1
    return RestoreResult(restored, identical, target)
