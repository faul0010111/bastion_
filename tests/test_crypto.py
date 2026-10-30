import base64
import json
import stat
import sys

import pytest

from bastion import crypto
from bastion.crypto import (
    MAX_FILES_PER_CALL,
    change_passphrase,
    decrypt_bytes,
    decrypt_file,
    encrypt_bytes,
    encrypt_file,
    generate_keyfile,
    load_key,
    plan_open,
    plan_protect,
    rotate_files,
)
from bastion.errors import CryptoError

PW = "a long and unique passphrase 123"


@pytest.fixture
def keyfile(tmp_path, fast_scrypt):
    path = tmp_path / "keys" / "key.json"
    generate_keyfile(path, PW, scrypt_params=fast_scrypt)
    return path


def test_roundtrip_bytes(keyfile):
    key = load_key(keyfile, PW)
    secret = "confidential report ✓".encode() * 100
    blob = encrypt_bytes(key, secret)
    assert secret not in blob and decrypt_bytes(key, blob) == secret


def test_each_encryption_is_different_but_decrypts(keyfile):
    key = load_key(keyfile, PW)
    a, b = encrypt_bytes(key, b"same text"), encrypt_bytes(key, b"same text")
    assert a != b and decrypt_bytes(key, a) == decrypt_bytes(key, b) == b"same text"


def test_wrong_passphrase_is_rejected(keyfile):
    with pytest.raises(CryptoError, match="Wrong passphrase"):
        load_key(keyfile, "a wrong but long passphrase")


def test_any_tampering_is_detected(keyfile):
    key = load_key(keyfile, PW)
    blob = bytearray(encrypt_bytes(key, b"important data"))
    for index in (len(blob) - 1, crypto.HEADER_LEN + 2, 10, 30, 45):  # tag, body, key_id, salt, nonce
        tampered = bytearray(blob)
        tampered[index] ^= 0x01
        with pytest.raises(CryptoError):
            decrypt_bytes(key, bytes(tampered))
    with pytest.raises(CryptoError):
        decrypt_bytes(key, bytes(blob[:-5]))              # truncated
    with pytest.raises(CryptoError):
        decrypt_bytes(key, b"this is not a bst file" * 5)  # invalid format


def test_file_from_another_key_is_refused(keyfile, tmp_path, fast_scrypt):
    other = tmp_path / "other.json"
    generate_keyfile(other, PW, scrypt_params=fast_scrypt)
    blob = encrypt_bytes(load_key(keyfile, PW), b"x" * 50)
    with pytest.raises(CryptoError, match="different key"):
        decrypt_bytes(load_key(other, PW), blob)


def test_keyfile_never_contains_the_raw_key_and_is_private(keyfile):
    raw = load_key(keyfile, PW).raw()
    content = keyfile.read_bytes()
    assert raw not in content and raw.hex().encode() not in content
    assert base64.b64encode(raw) not in content and PW.encode() not in content
    if sys.platform != "win32":
        assert stat.S_IMODE(keyfile.stat().st_mode) == 0o600


def test_key_never_overwritten(keyfile, fast_scrypt):
    before = keyfile.read_bytes()
    with pytest.raises(CryptoError, match="never overwrites"):
        generate_keyfile(keyfile, PW, scrypt_params=fast_scrypt)
    assert keyfile.read_bytes() == before


def test_short_passphrase_rejected(tmp_path, fast_scrypt):
    with pytest.raises(CryptoError, match="at least"):
        generate_keyfile(tmp_path / "k.json", "short", scrypt_params=fast_scrypt)


def test_datakey_hides_value(keyfile):
    key = load_key(keyfile, PW)
    assert key.raw().hex() not in repr(key) and key.raw().hex() not in str(key)
    assert "hidden" in repr(key)


def test_tampered_keyfile_params_are_bounded(keyfile):
    data = json.loads(keyfile.read_text())
    data["kdf"]["n"] = 2 ** 30  # attempt to exhaust memory
    keyfile.write_text(json.dumps(data))
    with pytest.raises(CryptoError):
        load_key(keyfile, PW)


def test_change_passphrase_keeps_data_readable(keyfile, tmp_path, fast_scrypt):
    blob = encrypt_bytes(load_key(keyfile, PW), b"still readable")
    change_passphrase(keyfile, PW, "another long passphrase 456", scrypt_params=fast_scrypt)
    with pytest.raises(CryptoError):
        load_key(keyfile, PW)
    assert decrypt_bytes(load_key(keyfile, "another long passphrase 456"), blob) == b"still readable"


def test_file_encrypt_decrypt_keeps_original(keyfile, tmp_path):
    key = load_key(keyfile, PW)
    src = tmp_path / "docs" / "report.txt"
    src.parent.mkdir()
    src.write_text("demo data")
    (src_plan, dst_plan), = plan_protect([str(src)], None, keyfile)
    encrypt_file(key, src_plan, dst_plan)
    assert src.read_text() == "demo data"                 # original preserved
    assert dst_plan.name == "report.txt.bst" and b"demo data" not in dst_plan.read_bytes()
    out_dir = tmp_path / "opened"
    out_dir.mkdir()
    (s, d), = plan_open([str(dst_plan)], out_dir)
    decrypt_file(key, s, d)
    assert d.read_text() == "demo data"


def test_no_silent_overwrite(keyfile, tmp_path):
    key = load_key(keyfile, PW)
    src = tmp_path / "docs" / "a.txt"
    src.parent.mkdir()
    src.write_text("1")
    (_, dst), = plan_protect([str(src)], None, keyfile)
    encrypt_file(key, src, dst)
    with pytest.raises(CryptoError, match="already exists"):
        encrypt_file(key, src, dst)


def test_plan_rejects_directories_and_mass_selection(keyfile, tmp_path):
    folder = tmp_path / "folder"
    folder.mkdir()
    with pytest.raises(Exception, match="folder"):
        plan_protect([str(folder)], None, keyfile)
    files = []
    for i in range(MAX_FILES_PER_CALL + 1):
        f = tmp_path / f"f{i}.txt"
        f.write_text("x")
        files.append(str(f))
    with pytest.raises(CryptoError, match="At most"):
        plan_protect(files, None, keyfile)


def test_plan_refuses_key_next_to_protected_files(tmp_path, fast_scrypt):
    docs = tmp_path / "docs"
    docs.mkdir()
    keyfile = docs / "key.json"
    generate_keyfile(keyfile, PW, scrypt_params=fast_scrypt)
    f = docs / "a.txt"
    f.write_text("x")
    with pytest.raises(CryptoError, match="same folder"):
        plan_protect([str(f)], None, keyfile)
    # also refuses when the destination of the encrypted files is the key's folder
    other = tmp_path / "other" / "b.txt"
    other.parent.mkdir()
    other.write_text("x")
    with pytest.raises(CryptoError, match="same folder"):
        plan_protect([str(other)], docs, keyfile)


def test_plan_refuses_keyfile_and_double_encryption(keyfile, tmp_path):
    with pytest.raises(CryptoError):
        plan_protect([str(keyfile)], tmp_path / "out", keyfile)
    already = tmp_path / "x.txt.bst"
    already.write_text("x")
    with pytest.raises(CryptoError, match="already looks protected"):
        plan_protect([str(already)], tmp_path / "out", keyfile)


def test_size_limit(keyfile, tmp_path, monkeypatch):
    monkeypatch.setattr(crypto, "MAX_FILE_BYTES", 100)
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 500)
    with pytest.raises(CryptoError, match="limit"):
        encrypt_file(load_key(keyfile, PW), big, tmp_path / "big.bin.bst")


def test_rotation_moves_files_to_new_key(keyfile, tmp_path, fast_scrypt):
    old_key = load_key(keyfile, PW)
    new_path = tmp_path / "new.json"
    generate_keyfile(new_path, PW, scrypt_params=fast_scrypt)
    new_key = load_key(new_path, PW)
    f = tmp_path / "a.txt.bst"
    f.write_bytes(encrypt_bytes(old_key, b"content"))
    rotate_files(old_key, new_key, [f])
    assert decrypt_bytes(new_key, f.read_bytes()) == b"content"
    with pytest.raises(CryptoError):
        decrypt_bytes(old_key, f.read_bytes())


def test_rotation_with_wrong_key_leaves_file_untouched(keyfile, tmp_path, fast_scrypt):
    other = tmp_path / "other.json"
    generate_keyfile(other, PW, scrypt_params=fast_scrypt)
    f = tmp_path / "a.txt.bst"
    original = encrypt_bytes(load_key(keyfile, PW), b"content")
    f.write_bytes(original)
    with pytest.raises(CryptoError):
        rotate_files(load_key(other, PW), load_key(other, PW), [f])
    assert f.read_bytes() == original


def test_header_has_no_filename_or_key(keyfile):
    key = load_key(keyfile, PW)
    blob = encrypt_bytes(key, b"x")
    assert blob[:4] == b"BST1" and key.raw() not in blob
