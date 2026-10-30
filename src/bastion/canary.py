"""Canary files (honeyfiles).

These are files no legitimate user has a reason to change. If one is modified,
disappears or is renamed, Bastion raises an immediate alert. The canary list
lives in the state directory, outside the monitored folder.

The names and content here are didactic and public (they are in this
repository). In real use, pick names and file types that are plausible for your
environment.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, List, Set

from .errors import BastionError
from .events import Event
from .fsutil import atomic_write_json

_DECOYS: Dict[str, str] = {
    "000-confidential-finance.txt": (
        "BASTION CANARY FILE (fictional content)\n"
        "Do not open, edit or move this file.\n"
        "Any change here raises a security alert.\n"
    ),
    "zzz-client-contracts.txt": (
        "BASTION CANARY FILE (fictional content)\n"
        "This file exists only to detect bulk changes.\n"
        "If you changed it by accident, tell whoever administers Bastion.\n"
    ),
}


def deploy_canaries(root: Path, canaries_file: Path) -> List[str]:
    """Create the canaries in ``root`` (never overwriting) and record them in the state."""
    created: Dict[str, str] = {}
    for name, text in _DECOYS.items():
        target = root / name
        if target.exists():
            raise BastionError(
                f"'{name}' already exists in {root}. Remove or move it before creating the canaries "
                "(Bastion does not overwrite existing files)."
            )
        created[name] = text
    for name, text in created.items():
        with open(root / name, "x", encoding="utf-8") as fh:
            fh.write(text)
    atomic_write_json(canaries_file, {
        "root": str(root),
        "files": {n: hashlib.sha256(t.encode("utf-8")).hexdigest() for n, t in created.items()},
    })
    return sorted(created)


def load_canary_hashes(canaries_file: Path) -> Dict[str, str]:
    """Canary name -> SHA-256 of the original content recorded at creation."""
    try:
        data = json.loads(Path(canaries_file).read_text(encoding="utf-8"))
        return {str(k): str(v) for k, v in data["files"].items()}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise BastionError(f"Canary file unreadable ({canaries_file}): {exc}") from None


def load_canaries(canaries_file: Path) -> Set[str]:
    return set(load_canary_hashes(canaries_file))


def canary_events(hashes: Dict[str, str], current: Dict[str, str], already: Set[str], now: float) -> List[Event]:
    """Synthetic events for canaries that vanished or changed since creation.

    ``current`` maps path -> current sha256; ``already`` holds paths that already
    have a change/removal event (to avoid duplicates).
    """
    out: List[Event] = []
    for name, original in sorted(hashes.items()):
        if name in already:
            continue
        sha = current.get(name)
        if sha is None:
            out.append(Event("deleted", name, now, source="verify"))
        elif sha != original:
            out.append(Event("modified", name, now, sha256=sha, source="verify"))
    return out
