"""Path and name validation.

General rule: paths coming from the user or from untrusted files (such as a
backup manifest) are validated before any use.
"""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path, PurePosixPath
from typing import Iterable, Optional

from .errors import PathValidationError


def _clean(raw: "str | os.PathLike[str]") -> Path:
    text = os.fspath(raw)
    if not text or not text.strip():
        raise PathValidationError("Empty path.")
    if "\x00" in text:
        raise PathValidationError("Path contains a null character.")
    return Path(text).expanduser()


def resolve_existing_dir(
    raw: "str | os.PathLike[str]", *, label: str = "folder", allow_fs_root: bool = False
) -> Path:
    """Resolve and validate an existing, readable directory."""
    path = _clean(raw)
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError:
        raise PathValidationError(f"Folder not found ({label}): {path}") from None
    except (OSError, RuntimeError) as exc:
        raise PathValidationError(f"Cannot access '{path}' ({label}): {exc}") from None
    if not resolved.is_dir():
        raise PathValidationError(f"Path is not a folder ({label}): {resolved}")
    if not allow_fs_root and resolved.parent == resolved:
        raise PathValidationError(
            "Refused: the filesystem root cannot be used here. Choose a specific folder."
        )
    if not os.access(resolved, os.R_OK | os.X_OK):
        raise PathValidationError(f"No read permission on folder ({label}): {resolved}")
    return resolved


def resolve_existing_file(raw: "str | os.PathLike[str]", *, label: str = "file") -> Path:
    """Resolve and validate an existing, readable regular file."""
    path = _clean(raw)
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError:
        raise PathValidationError(f"File not found ({label}): {path}") from None
    except (OSError, RuntimeError) as exc:
        raise PathValidationError(f"Cannot access '{path}' ({label}): {exc}") from None
    if resolved.is_dir():
        raise PathValidationError(
            f"'{resolved}' is a folder. Select files explicitly ({label})."
        )
    if not resolved.is_file():
        raise PathValidationError(f"Not a regular file ({label}): {resolved}")
    if not os.access(resolved, os.R_OK):
        raise PathValidationError(f"No read permission on file ({label}): {resolved}")
    return resolved


def resolve_path(raw: "str | os.PathLike[str]") -> Path:
    """Resolve a path that may not exist yet."""
    try:
        return _clean(raw).resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise PathValidationError(f"Invalid path '{raw}': {exc}") from None


def is_within(child: "str | os.PathLike[str]", parent: "str | os.PathLike[str]") -> bool:
    """True if ``child`` is ``parent`` or lives inside it (after resolving links)."""
    try:
        Path(child).resolve().relative_to(Path(parent).resolve())
        return True
    except (ValueError, OSError, RuntimeError):
        return False


def ensure_disjoint(a: Path, b: Path, *, label_a: str, label_b: str) -> None:
    """Make sure two folders are not nested inside one another."""
    if is_within(a, b) or is_within(b, a):
        raise PathValidationError(
            f"{label_a} ('{a}') and {label_b} ('{b}') cannot be nested inside each other. "
            "Keeping these areas separate is part of the protection."
        )


def to_relative_posix(path: "str | os.PathLike[str]", root: Path) -> Optional[str]:
    """Path relative to ``root`` in POSIX form, or None if it is outside ``root``."""
    try:
        return Path(path).relative_to(root).as_posix()
    except ValueError:
        return None


def safe_relative_join(base: Path, rel: str) -> Path:
    """Join ``rel`` (untrusted data) to ``base`` without ever escaping ``base``."""
    if not isinstance(rel, str) or not rel or "\x00" in rel:
        raise PathValidationError(f"Invalid relative path: {rel!r}")
    pure = PurePosixPath(rel)
    if pure.is_absolute() or ".." in pure.parts or pure.parts in ((), (".",)):
        raise PathValidationError(f"Unsafe relative path: {rel!r}")
    target = base.joinpath(*pure.parts)
    if not is_within(target, base):
        raise PathValidationError(f"Path would escape the target folder: {rel!r}")
    return target


def is_ignored(rel_posix: str, patterns: Iterable[str]) -> bool:
    """True if the relative path (or just its name) matches any glob pattern."""
    name = rel_posix.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(rel_posix, p) or fnmatch.fnmatch(name, p) for p in patterns)
