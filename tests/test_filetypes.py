import os

import pytest
from hypothesis import given
from hypothesis import strategies as st

from bastion.filetypes import (
    EMPTY,
    KNOWN_FORMATS,
    TEXT,
    UNKNOWN,
    detect_type,
    lost_known_header,
)
from bastion.fingerprint import fingerprint_file


@pytest.mark.parametrize("head,label", [
    (b"%PDF-1.7\n%\xe2\xe3", "pdf"),
    (b"PK\x03\x04\x14\x00\x06\x00", "zip"),
    (b"\x89PNG\r\n\x1a\n\x00\x00", "png"),
    (b"\xff\xd8\xff\xe0\x00\x10JFIF", "jpeg"),
    (b"GIF89a\x01\x00", "gif"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1rest", "ole"),
    (b"\x1f\x8b\x08\x00", "gzip"),
    (b"SQLite format 3\x00" + b"\x00" * 20, "sqlite"),
    (b"\x00\x00\x00\x18ftypmp42", "mp4"),
])
def test_known_signatures(head, label):
    assert detect_type(head) == label


def test_text_empty_and_unknown():
    assert detect_type(b"") == EMPTY
    assert detect_type("plain report with accents: ação ✓\n".encode()) == TEXT
    assert detect_type(b"name,amount\nAna,10\n") == TEXT
    assert detect_type(b"\x00\x01\x02\x03binary\xff\xfe") == UNKNOWN


def test_text_cut_in_the_middle_of_a_multibyte_character_is_still_text():
    data = ("é" * 600).encode()[:1023]      # 1023 bytes: last character is cut in half
    assert detect_type(data) == TEXT


def test_random_bytes_are_unknown():
    unknown = sum(detect_type(os.urandom(2048)) == UNKNOWN for _ in range(200))
    assert unknown == 200


def test_lost_known_header_semantics():
    assert lost_known_header("zip", UNKNOWN)
    assert lost_known_header("pdf", UNKNOWN)
    assert not lost_known_header("zip", "zip")
    assert not lost_known_header(TEXT, UNKNOWN)       # plain text never had a header to lose
    assert not lost_known_header(UNKNOWN, UNKNOWN)
    assert not lost_known_header("", UNKNOWN)         # inventories written by Bastion 0.1
    assert not lost_known_header(None, UNKNOWN)
    assert not lost_known_header("zip", "pdf")        # a different known format is not "lost"


def test_fingerprint_reports_magic(tmp_path):
    f = tmp_path / "doc.pdf"
    f.write_bytes(b"%PDF-1.4\n" + os.urandom(3000))
    assert fingerprint_file(f).magic == "pdf"
    f.write_bytes(os.urandom(3000))
    assert fingerprint_file(f).magic == UNKNOWN
    (tmp_path / "empty").write_bytes(b"")
    assert fingerprint_file(tmp_path / "empty").magic == EMPTY


@given(st.binary(max_size=4096))
def test_detect_type_is_total(data):
    label = detect_type(data)
    assert label in KNOWN_FORMATS | {TEXT, EMPTY, UNKNOWN}


@given(st.binary(max_size=2048))
def test_pdf_prefix_always_wins(tail):
    assert detect_type(b"%PDF-" + tail) == "pdf"
