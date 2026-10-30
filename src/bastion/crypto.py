"""Encryption of explicitly selected files.

No home-made algorithms: everything comes from the ``cryptography`` library.

Key management
--------------
* **Creation**: a random 256-bit *data key* (``os.urandom``).
* **Protection at rest**: the data key lives in a JSON *key file*, encrypted
  with AES-256-GCM under a key derived from your passphrase via scrypt
  (parameters are stored in the file). Without the passphrase the file does not
  reveal the key.
* **Storage**: the key file is never written next to the protected files
  (``plan_protect`` refuses) and is created with 0600 permissions, never
  overwriting an existing one.
* **Use**: every file gets its own *subkey* (HKDF-SHA256 with a random salt)
  and a random nonce; the whole header is authenticated (AAD).
* **Replacement**: ``change_passphrase`` only changes the passphrase (re-wraps
  the same key); ``rotate_files`` replaces the data key and re-encrypts files.
* **Logs**: keys and passphrases are never logged; ``DataKey`` hides its value
  in ``repr``/``str``.
"""

from __future__ import annotations

import base64
import json
import os
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import CryptoError
from .fsutil import atomic_write_bytes
from .paths import is_within, resolve_existing_file, resolve_path

MAGIC = b"BST1"
FORMAT_VERSION = 1
KEY_BYTES, SALT_BYTES, NONCE_BYTES, KEY_ID_BYTES, TAG_BYTES = 32, 16, 12, 16, 16
HEADER_LEN = len(MAGIC) + 1 + KEY_ID_BYTES + SALT_BYTES + NONCE_BYTES
ENCRYPTED_SUFFIX = ".bst"
MAX_FILE_BYTES = 64 * 1024 * 1024   # selected files, not whole volumes
MAX_FILES_PER_CALL = 20             # guard against indiscriminate use
MIN_PASSPHRASE_LEN = 12
_HKDF_INFO = b"bastion-file-key-v1"
_WRAP_AAD = b"bastion-keyfile-v1|"


@dataclass(frozen=True)
class ScryptParams:
    n: int = 2 ** 17
    r: int = 8
    p: int = 1


DEFAULT_SCRYPT = ScryptParams()


class DataKey:
    """In-memory data key. Never prints its value."""

    __slots__ = ("_raw", "key_id")

    def __init__(self, key_id: bytes, raw: bytes) -> None:
        self.key_id = key_id
        self._raw = raw

    def raw(self) -> bytes:
        return self._raw

    def __repr__(self) -> str:
        return f"DataKey(key_id={self.key_id.hex()}, value=<hidden>)"

    __str__ = __repr__


# -- passphrase and key file ------------------------------------------------------

def _pass_bytes(passphrase: str) -> bytes:
    return unicodedata.normalize("NFKC", passphrase).encode("utf-8")


def _kek(passphrase: str, salt: bytes, params: ScryptParams) -> bytes:
    return Scrypt(salt=salt, length=KEY_BYTES, n=params.n, r=params.r, p=params.p).derive(_pass_bytes(passphrase))


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _check_params(params: ScryptParams) -> None:
    n, r, p = params.n, params.r, params.p
    if n < 2 ** 10 or n > 2 ** 22 or n & (n - 1):
        raise CryptoError("Invalid scrypt parameter 'n' in the key file.")
    if not (1 <= r <= 32 and 1 <= p <= 16) or 128 * n * r > 2 ** 30:
        raise CryptoError("scrypt parameters outside safe limits.")


def validate_scrypt_params(params: ScryptParams) -> None:
    """Public wrapper: raise CryptoError when the parameters are outside safe limits."""
    _check_params(params)


def wrap_secret(raw: bytes, key_id: bytes, passphrase: str, params: ScryptParams,
                aad_prefix: bytes = _WRAP_AAD) -> dict:
    """Seal ``raw`` under a passphrase (scrypt + AES-256-GCM). Shared by data keys and signing keys."""
    salt, nonce = os.urandom(SALT_BYTES), os.urandom(NONCE_BYTES)
    sealed = AESGCM(_kek(passphrase, salt, params)).encrypt(nonce, raw, aad_prefix + key_id)
    return {
        "version": FORMAT_VERSION,
        "key_id": key_id.hex(),
        "kdf": {"name": "scrypt", "salt": _b64(salt), "n": params.n, "r": params.r, "p": params.p},
        "wrapped_key": {"cipher": "AES-256-GCM", "nonce": _b64(nonce), "ciphertext": _b64(sealed)},
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def check_new_passphrase(passphrase: str) -> None:
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        raise CryptoError(f"The passphrase must be at least {MIN_PASSPHRASE_LEN} characters long.")


def write_new_private_file(path: Path, payload: bytes, what: str = "key file") -> None:
    """Create ``path`` with 0600 permissions. Never overwrites an existing file."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise CryptoError(
            f"A {what} already exists at {path}. Bastion never overwrites keys "
            "(losing one means losing access to your files or your ability to sign). Choose another path."
        ) from None
    with os.fdopen(fd, "wb") as fh:
        fh.write(payload)


def generate_keyfile(path: Path, passphrase: str, *, scrypt_params: ScryptParams = DEFAULT_SCRYPT) -> str:
    """Create a new key file (0600). Never overwrites. Returns the key_id."""
    check_new_passphrase(passphrase)
    _check_params(scrypt_params)
    path = resolve_path(path)
    key_id, raw = os.urandom(KEY_ID_BYTES), os.urandom(KEY_BYTES)
    payload = json.dumps(wrap_secret(raw, key_id, passphrase, scrypt_params), indent=2).encode() + b"\n"
    write_new_private_file(path, payload)
    return key_id.hex()


def read_wrapped_secret(path: Path, passphrase: str, aad_prefix: bytes = _WRAP_AAD,
                        what: str = "Key file") -> Tuple[bytes, bytes]:
    """Open a passphrase-sealed JSON document. Returns ``(key_id, secret)``."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data["version"] != FORMAT_VERSION or data["kdf"]["name"] != "scrypt":
            raise CryptoError(f"Unsupported {what.lower()} format.")
        key_id = bytes.fromhex(data["key_id"])
        params = ScryptParams(int(data["kdf"]["n"]), int(data["kdf"]["r"]), int(data["kdf"]["p"]))
        salt = _unb64(data["kdf"]["salt"])
        nonce = _unb64(data["wrapped_key"]["nonce"])
        sealed = _unb64(data["wrapped_key"]["ciphertext"])
    except CryptoError:
        raise
    except FileNotFoundError:
        raise CryptoError(f"{what} not found: {path}") from None
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise CryptoError(f"{what} unreadable or corrupted ({path}): {exc}") from None
    if len(key_id) != KEY_ID_BYTES or len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES:
        raise CryptoError(f"{what} has fields with invalid sizes.")
    _check_params(params)
    try:
        raw = AESGCM(_kek(passphrase, salt, params)).decrypt(nonce, sealed, aad_prefix + key_id)
    except InvalidTag:
        raise CryptoError(f"Wrong passphrase or tampered {what.lower()}.") from None
    return key_id, raw


def load_key(path: Path, passphrase: str) -> DataKey:
    return DataKey(*read_wrapped_secret(path, passphrase))


def change_passphrase(path: Path, old: str, new: str, *, scrypt_params: ScryptParams = DEFAULT_SCRYPT) -> None:
    """Re-wrap the SAME data key under a new passphrase (existing files keep opening)."""
    check_new_passphrase(new)
    _check_params(scrypt_params)
    key = load_key(path, old)
    payload = json.dumps(wrap_secret(key.raw(), key.key_id, new, scrypt_params), indent=2).encode() + b"\n"
    atomic_write_bytes(Path(path), payload, mode=0o600)


# -- files -------------------------------------------------------------------------

def _file_key(key: DataKey, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=salt, info=_HKDF_INFO).derive(key.raw())


def encrypt_bytes(key: DataKey, plaintext: bytes) -> bytes:
    salt, nonce = os.urandom(SALT_BYTES), os.urandom(NONCE_BYTES)
    header = MAGIC + bytes([FORMAT_VERSION]) + key.key_id + salt + nonce
    return header + AESGCM(_file_key(key, salt)).encrypt(nonce, plaintext, header)


def decrypt_bytes(key: DataKey, blob: bytes) -> bytes:
    if len(blob) < HEADER_LEN + TAG_BYTES or blob[:4] != MAGIC:
        raise CryptoError("Not a file protected by Bastion (invalid header).")
    if blob[4] != FORMAT_VERSION:
        raise CryptoError(f"Unsupported format version: {blob[4]}.")
    header = blob[:HEADER_LEN]
    off = len(MAGIC) + 1
    key_id = header[off:off + KEY_ID_BYTES]
    salt = header[off + KEY_ID_BYTES: off + KEY_ID_BYTES + SALT_BYTES]
    nonce = header[off + KEY_ID_BYTES + SALT_BYTES:]
    if key_id != key.key_id:
        raise CryptoError(f"This file was protected with a different key (id {key_id.hex()[:8]}…).")
    try:
        return AESGCM(_file_key(key, salt)).decrypt(nonce, blob[HEADER_LEN:], header)
    except InvalidTag:
        raise CryptoError("Authentication failed: the file was tampered with, is corrupted, or the key does not match.") from None


def _read_limited(path: Path, limit: int) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise CryptoError(f"'{path.name}' is {size} bytes; this tool's limit is {limit} (it is for selected files, not whole volumes).")
    return path.read_bytes()


def plan_protect(files: Sequence[str], out_dir: Optional[Path], keyfile: Path) -> List[Tuple[Path, Path]]:
    """Validate the selection and return (source, destination) pairs. Writes nothing."""
    if not files:
        raise CryptoError("Provide at least one file.")
    if len(files) > MAX_FILES_PER_CALL:
        raise CryptoError(f"At most {MAX_FILES_PER_CALL} files per call: Bastion protects explicit selections, not whole folders.")
    keyfile = resolve_path(keyfile)
    dest_dir = resolve_path(out_dir) if out_dir else None
    plan: List[Tuple[Path, Path]] = []
    for raw in files:
        src = resolve_existing_file(raw, label="file to protect")  # rejects folders
        if src == keyfile:
            raise CryptoError("Protecting the key file itself is not allowed.")
        if src.name.endswith(ENCRYPTED_SUFFIX):
            raise CryptoError(f"'{src.name}' already looks protected (extension {ENCRYPTED_SUFFIX}).")
        dst_dir = dest_dir or src.parent
        if keyfile.parent == dst_dir or keyfile.parent == src.parent or is_within(keyfile, dst_dir):
            raise CryptoError(
                f"The key file ({keyfile}) is in the same folder as the protected files. "
                "Store the key somewhere else (e.g. a USB drive or a password manager)."
            )
        plan.append((src, dst_dir / (src.name + ENCRYPTED_SUFFIX)))
    return plan


def encrypt_file(key: DataKey, src: Path, dst: Path, *, overwrite: bool = False) -> None:
    """Encrypt ``src`` into ``dst``. The original is kept."""
    if dst.exists() and not overwrite:
        raise CryptoError(f"Destination already exists: {dst}")
    atomic_write_bytes(dst, encrypt_bytes(key, _read_limited(src, MAX_FILE_BYTES)), mode=0o600)


def plan_open(files: Sequence[str], out_dir: Optional[Path]) -> List[Tuple[Path, Path]]:
    if not files:
        raise CryptoError("Provide at least one file.")
    if len(files) > MAX_FILES_PER_CALL:
        raise CryptoError(f"At most {MAX_FILES_PER_CALL} files per call.")
    dest_dir = resolve_path(out_dir) if out_dir else None
    plan = []
    for raw in files:
        src = resolve_existing_file(raw, label="protected file")
        if not src.name.endswith(ENCRYPTED_SUFFIX) or len(src.name) == len(ENCRYPTED_SUFFIX):
            raise CryptoError(f"'{src.name}' does not have the {ENCRYPTED_SUFFIX} extension.")
        plan.append((src, (dest_dir or src.parent) / src.name[: -len(ENCRYPTED_SUFFIX)]))
    return plan


def decrypt_file(key: DataKey, src: Path, dst: Path, *, overwrite: bool = False) -> None:
    if dst.exists() and not overwrite:
        raise CryptoError(f"Destination already exists: {dst}")
    plain = decrypt_bytes(key, _read_limited(src, MAX_FILE_BYTES + HEADER_LEN + TAG_BYTES))
    atomic_write_bytes(dst, plain, mode=0o600)


def rotate_files(old_key: DataKey, new_key: DataKey, files: Sequence[Path]) -> List[Path]:
    """Re-encrypt .bst files from the old key to the new one (each swap is atomic)."""
    if len(files) > MAX_FILES_PER_CALL:
        raise CryptoError(f"At most {MAX_FILES_PER_CALL} files per call.")
    done: List[Path] = []
    for path in files:
        blob = _read_limited(path, MAX_FILE_BYTES + HEADER_LEN + TAG_BYTES)
        plain = decrypt_bytes(old_key, blob)  # fails before touching the file
        atomic_write_bytes(path, encrypt_bytes(new_key, plain), mode=0o600)
        done.append(path)
    return done
