"""Content-based file type detection from the first bytes of a file.

Bastion uses this for one narrow purpose: noticing that a file which used to
start with a well-known header (PDF, ZIP/Office, PNG, JPEG...) no longer does.
Documents that are already compressed (``.docx``, ``.zip``, ``.jpg``) have high
entropy from the start, so an entropy *jump* cannot reveal that their content
was replaced; losing the header can.

Detection is intentionally small and conservative: a short table of widely
documented signatures, plus a plain-text heuristic. Anything else is
``"unknown"``.
"""

from __future__ import annotations

from typing import Tuple

HEAD_BYTES = 1024

EMPTY = "empty"
TEXT = "text"
UNKNOWN = "unknown"

# (offset, signature, label). Only widely documented, unambiguous prefixes.
_SIGNATURES: Tuple[Tuple[int, bytes, str], ...] = (
    (0, b"%PDF-", "pdf"),
    (0, b"PK\x03\x04", "zip"),            # also docx/xlsx/pptx/odt/jar/apk
    (0, b"PK\x05\x06", "zip"),
    (0, b"\x89PNG\r\n\x1a\n", "png"),
    (0, b"\xff\xd8\xff", "jpeg"),
    (0, b"GIF87a", "gif"),
    (0, b"GIF89a", "gif"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),   # legacy .doc/.xls/.ppt
    (0, b"\x1f\x8b\x08", "gzip"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z"),
    (0, b"Rar!\x1a\x07", "rar"),
    (0, b"SQLite format 3\x00", "sqlite"),
    (0, b"\x7fELF", "elf"),
    (0, b"OggS", "ogg"),
    (0, b"fLaC", "flac"),
    (0, b"ID3", "mp3"),
    (0, b"RIFF", "riff"),                 # wav/avi/webp
    (4, b"ftyp", "mp4"),                  # mp4/mov/heic
)

#: Labels that mean "a recognizable binary format" (as opposed to text/unknown).
KNOWN_FORMATS = frozenset(label for _, _, label in _SIGNATURES)


def _looks_like_text(head: bytes) -> bool:
    if not head or b"\x00" in head:
        return False
    try:
        head.decode("utf-8")
        return True
    except UnicodeDecodeError as exc:
        if exc.start >= len(head) - 3:     # we merely cut a multi-byte character
            return True
    printable = sum(1 for b in head if b in (9, 10, 13) or 32 <= b < 127 or b >= 160)
    return printable / len(head) >= 0.95


def detect_type(head: bytes) -> str:
    """Return a format label, ``"text"``, ``"empty"`` or ``"unknown"``."""
    head = head[:HEAD_BYTES]
    if not head:
        return EMPTY
    for offset, signature, label in _SIGNATURES:
        if head[offset:offset + len(signature)] == signature:
            return label
    return TEXT if _looks_like_text(head) else UNKNOWN


def lost_known_header(previous: str | None, current: str | None) -> bool:
    """True when a file went from a recognized binary format to something unrecognized."""
    return bool(previous in KNOWN_FORMATS and current == UNKNOWN)
