"""File fingerprints: SHA-256, Shannon entropy and content type.

Entropy (0 to 8 bits/byte) is computed over the first 1 MiB. Plain text sits
around 3.5 to 5; encrypted or compressed data sits near 8. What Bastion cares
about is the *jump* in entropy within the same file, not the absolute value,
because ``.zip`` and ``.jpg`` files are born with high entropy.
"""

from __future__ import annotations

import hashlib
import math
import os
import stat
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .filetypes import detect_type

CHUNK_SIZE = 1024 * 1024
ENTROPY_SAMPLE_BYTES = CHUNK_SIZE


@dataclass(frozen=True)
class Fingerprint:
    sha256: str
    size: int
    entropy: float
    magic: str = ""   # content-based type label, see filetypes.detect_type


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in Counter(data).values())


def is_regular_file(path: "str | os.PathLike[str]") -> bool:
    """True for regular files; False for links, folders, FIFOs and missing paths."""
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def fingerprint_file(path: "str | os.PathLike[str]") -> Fingerprint:
    """Read the file once, in blocks. May raise OSError."""
    digest = hashlib.sha256()
    sample = b""
    magic = detect_type(b"")
    size = 0
    with open(Path(path), "rb") as fh:
        first = True
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            if first:
                sample = chunk[:ENTROPY_SAMPLE_BYTES]
                magic = detect_type(chunk)
                first = False
            digest.update(chunk)
            size += len(chunk)
    return Fingerprint(digest.hexdigest(), size, round(shannon_entropy(sample), 4), magic)
