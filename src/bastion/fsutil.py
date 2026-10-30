"""Filesystem helpers: atomic writes and overwrite confirmation."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from .errors import BastionError

_COPY_CHUNK = 1024 * 1024


def _tmp_in(directory: Path, name: str) -> "tuple[int, str]":
    directory.mkdir(parents=True, exist_ok=True)
    return tempfile.mkstemp(dir=directory, prefix=f".{name}.", suffix=".tmp")


def atomic_write_bytes(path: Path, data: bytes, mode: Optional[int] = None) -> None:
    """Write to a temp file and rename it: never leaves a half-written file."""
    fd, tmp = _tmp_in(path.parent, path.name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def atomic_write_json(path: Path, obj: Any, mode: Optional[int] = None) -> None:
    text = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    atomic_write_bytes(path, text.encode("utf-8"), mode)


def atomic_copy(src: Path, dst: Path) -> None:
    """Copy ``src`` to ``dst`` atomically, preserving permissions and timestamps."""
    fd, tmp = _tmp_in(dst.parent, dst.name)
    try:
        with os.fdopen(fd, "wb") as out, open(src, "rb") as inp:
            shutil.copyfileobj(inp, out, _COPY_CHUNK)
            out.flush()
            os.fsync(out.fileno())
        with contextlib.suppress(OSError):
            shutil.copystat(src, tmp)
        os.replace(tmp, dst)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def confirm_overwrite(
    collisions: Sequence[Path],
    *,
    allow_overwrite: bool,
    assume_yes: bool,
    input_fn: Callable[[str], str] = input,
    is_tty: Optional[bool] = None,
) -> None:
    """Require explicit confirmation before overwriting any file.

    - No collisions: nothing to do.
    - Collisions without ``--overwrite``: refuse.
    - With ``--overwrite``: ask in an interactive terminal; in non-interactive
      mode ``--yes`` is also required.
    """
    if not collisions:
        return
    shown = "\n".join(f"  - {p}" for p in list(collisions)[:10])
    extra = f"\n  ... and {len(collisions) - 10} more" if len(collisions) > 10 else ""
    if not allow_overwrite:
        raise BastionError(
            f"{len(collisions)} file(s) already exist at the destination and were NOT changed:\n"
            f"{shown}{extra}\n"
            "Choose another destination, or use --overwrite if you really want to replace them."
        )
    if assume_yes:
        return
    tty = sys.stdin.isatty() if is_tty is None else is_tty
    if not tty:
        raise BastionError(
            "Overwrite requested, but there is no interactive terminal to confirm it. "
            "Add --yes to confirm explicitly."
        )
    answer = input_fn(
        f"This will REPLACE {len(collisions)} file(s):\n{shown}{extra}\nType 'yes' to continue: "
    )
    if answer.strip().lower() != "yes":
        raise BastionError("Operation cancelled: nothing was overwritten.")
