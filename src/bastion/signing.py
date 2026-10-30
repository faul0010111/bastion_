"""Signed log checkpoints (Ed25519).

The hash chain proves that a log was not edited *internally*, but whoever can
write the file can rebuild the whole chain. A **checkpoint** closes that gap: it
is a small document stating "the log had N records and its head hash was H",
signed with a private key that is **not** the monitored machine's business.

* The private key is generated once (``bastion sign keygen``) and sealed under
  a passphrase with the same scrypt + AES-256-GCM wrapping used for data keys.
  Ideally it lives on a different machine or removable media.
* A checkpoint can be created at any time and stored anywhere (email it to
  yourself, print it, keep it in a ticket). Verification needs only the
  **public** key, so it can be done on any computer.
* Verifying a checkpoint checks the signature, then that the log still contains
  record N with exactly that hash. Rewriting history before N, truncating the
  log below N or swapping the whole file are all detected, even if the attacker
  rebuilt a self-consistent chain.

What it does not do: it cannot prove the log is *complete* after the last
checkpoint, so create checkpoints regularly. Anyone holding the private key and
its passphrase can sign anything: protect them.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .crypto import (
    DEFAULT_SCRYPT,
    ScryptParams,
    check_new_passphrase,
    read_wrapped_secret,
    validate_scrypt_params,
    wrap_secret,
    write_new_private_file,
)
from .errors import CryptoError, SigningError
from .eventlog import verify_log
from .paths import resolve_path

CHECKPOINT_TYPE = "bastion-log-checkpoint"
CHECKPOINT_VERSION = 1
PUBLIC_KEY_VERSION = 1
_SIGN_AAD = b"bastion-signing-key-v1|"
MAX_CHECKPOINT_BYTES = 64 * 1024


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: Any) -> bytes:
    if not isinstance(text, str):
        raise SigningError("Malformed base64 field.")
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        raise SigningError("Malformed base64 field.") from None


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id_for(public_raw: bytes) -> bytes:
    """16-byte identifier derived from the public key (safe to print and compare)."""
    return hashlib.sha256(public_raw).digest()[:16]


# -- keys ----------------------------------------------------------------------------

@dataclass(frozen=True)
class PublicKey:
    key_id: str
    key: Ed25519PublicKey


def generate_signing_keypair(
    private_path: Path,
    public_path: Path,
    passphrase: str,
    *,
    scrypt_params: ScryptParams = DEFAULT_SCRYPT,
) -> str:
    """Create a passphrase-sealed private key (0600) and a public key file. Never overwrites."""
    check_new_passphrase(passphrase)
    validate_scrypt_params(scrypt_params)
    private_path, public_path = resolve_path(private_path), resolve_path(public_path)
    if private_path == public_path:
        raise SigningError("The private and public key files must be different paths.")
    private = Ed25519PrivateKey.generate()
    seed = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
    public_raw = _raw_public(private.public_key())
    key_id = key_id_for(public_raw)
    sealed = wrap_secret(seed, key_id, passphrase, scrypt_params, aad_prefix=_SIGN_AAD)
    sealed["algorithm"] = "Ed25519"
    sealed["public_key"] = _b64(public_raw)
    public_doc = {"version": PUBLIC_KEY_VERSION, "algorithm": "Ed25519",
                  "key_id": key_id.hex(), "public_key": _b64(public_raw)}
    if public_path.exists():
        raise SigningError(f"A file already exists at {public_path}. Bastion never overwrites keys.")
    write_new_private_file(private_path, json.dumps(sealed, indent=2).encode() + b"\n", "signing key")
    try:
        write_new_private_file(public_path, json.dumps(public_doc, indent=2).encode() + b"\n",
                               "public key")
        os.chmod(public_path, 0o644)          # a public key is meant to be shared
    except Exception:
        private_path.unlink(missing_ok=True)   # do not leave a half-created pair behind
        raise
    return key_id.hex()


def load_private_key(path: Path, passphrase: str) -> Tuple[Ed25519PrivateKey, str]:
    try:
        key_id, seed = read_wrapped_secret(path, passphrase, aad_prefix=_SIGN_AAD, what="Signing key")
    except CryptoError as exc:
        raise SigningError(str(exc)) from None
    if len(seed) != 32:
        raise SigningError("Signing key has an invalid size.")
    private = Ed25519PrivateKey.from_private_bytes(seed)
    if key_id_for(_raw_public(private.public_key())) != key_id:
        raise SigningError("Signing key file is inconsistent (identifier mismatch).")
    return private, key_id.hex()


def load_public_key(path: Path) -> PublicKey:
    try:
        text = Path(path).read_text(encoding="utf-8")
        if len(text) > MAX_CHECKPOINT_BYTES:
            raise SigningError("Public key file is unexpectedly large.")
        data = json.loads(text)
        if data["version"] != PUBLIC_KEY_VERSION or data["algorithm"] != "Ed25519":
            raise SigningError("Unsupported public key format.")
        raw = _unb64(data["public_key"])
        if len(raw) != 32:
            raise SigningError("Public key has an invalid size.")
        key_id = key_id_for(raw).hex()
        if data.get("key_id") != key_id:
            raise SigningError("Public key file is inconsistent (identifier mismatch).")
        return PublicKey(key_id, Ed25519PublicKey.from_public_bytes(raw))
    except SigningError:
        raise
    except FileNotFoundError:
        raise SigningError(f"Public key not found: {path}") from None
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SigningError(f"Public key unreadable or corrupted ({path}): {exc}") from None


# -- checkpoints -----------------------------------------------------------------------

def _signed_body(doc: Dict[str, Any]) -> bytes:
    return _canonical({k: v for k, v in doc.items() if k != "signature"})


def create_checkpoint(
    log_path: Path,
    private: Ed25519PrivateKey,
    key_id: str,
    *,
    now: Optional[float] = None,
    note: str = "",
) -> Dict[str, Any]:
    """Sign "this log has N records and this head hash". Refuses to sign a broken chain."""
    check = verify_log(Path(log_path))
    if not check.ok:
        raise SigningError(
            f"Refusing to sign: the log chain does not verify ({check.error}). "
            "Preserve the file as evidence instead.")
    if check.records == 0:
        raise SigningError("The log is empty; there is nothing to sign yet.")
    ts = datetime.now(timezone.utc) if now is None else datetime.fromtimestamp(now, tz=timezone.utc)
    doc: Dict[str, Any] = {
        "type": CHECKPOINT_TYPE,
        "version": CHECKPOINT_VERSION,
        "created_at": ts.isoformat(timespec="seconds"),
        "records": check.records,
        "head": check.head,
        "key_id": key_id,
    }
    if note:
        doc["note"] = note[:200]
    doc["signature"] = _b64(private.sign(_signed_body(doc)))
    return doc


def parse_checkpoint(text: str) -> Dict[str, Any]:
    if len(text) > MAX_CHECKPOINT_BYTES:
        raise SigningError("Checkpoint is unexpectedly large.")
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise SigningError(f"Checkpoint is not valid JSON: {exc}") from None
    if not isinstance(doc, dict) or doc.get("type") != CHECKPOINT_TYPE:
        raise SigningError("This is not a Bastion log checkpoint.")
    if doc.get("version") != CHECKPOINT_VERSION:
        raise SigningError(f"Unsupported checkpoint version: {doc.get('version')!r}.")
    records, head = doc.get("records"), doc.get("head")
    if isinstance(records, bool) or not isinstance(records, int) or records < 1:
        raise SigningError("Checkpoint has an invalid record count.")
    if not (isinstance(head, str) and len(head) == 64 and all(c in "0123456789abcdef" for c in head)):
        raise SigningError("Checkpoint has an invalid head hash.")
    if not isinstance(doc.get("key_id"), str) or not isinstance(doc.get("signature"), str):
        raise SigningError("Checkpoint is missing its key id or signature.")
    return doc


def load_checkpoints(path: Path) -> List[Dict[str, Any]]:
    """Read a checkpoint file: a single JSON document or JSON Lines. Skips nothing silently."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SigningError(f"Checkpoint file not found: {path}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise SigningError(f"Could not read checkpoint file {path}: {exc}") from None
    stripped = text.strip()
    if not stripped:
        raise SigningError(f"Checkpoint file {path} is empty.")
    try:                                       # a single (possibly pretty-printed) document
        return [parse_checkpoint(stripped)]
    except SigningError as single_error:
        lines = [line for line in stripped.splitlines() if line.strip()]
        if len(lines) < 2:
            raise single_error from None
    return [parse_checkpoint(line) for line in lines]   # JSON Lines


def append_checkpoint(path: Path, doc: Dict[str, Any]) -> None:
    """Append one checkpoint as a JSON line to a local checkpoints file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(doc, sort_keys=True, ensure_ascii=False) + "\n")


@dataclass
class CheckpointResult:
    ok: bool
    records: int            # N in the checkpoint
    created_at: str
    error: Optional[str] = None
    records_since: int = 0  # records appended to the log after the checkpoint


def hash_at(log_path: Path, seq: int) -> Optional[str]:
    """Hash of record ``seq`` in the log, or None when the log is shorter."""
    with open(log_path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                return None
            if rec.get("seq") == seq:
                return str(rec.get("hash"))
    return None


def verify_checkpoint(log_path: Path, doc: Dict[str, Any], public: PublicKey) -> CheckpointResult:
    """Check signature, key identity, chain integrity and that record N still has the signed hash."""
    count, created = int(doc["records"]), str(doc.get("created_at", "?"))

    def fail(message: str) -> CheckpointResult:
        return CheckpointResult(False, count, created, error=message)

    if doc["key_id"] != public.key_id:
        return fail(f"Checkpoint was signed by key {doc['key_id'][:8]}…, not by the given public key "
                    f"({public.key_id[:8]}…).")
    try:
        public.key.verify(_unb64(doc["signature"]), _signed_body(doc))
    except (InvalidSignature, SigningError):
        return fail("The checkpoint signature is INVALID (forged or altered checkpoint).")
    log_path = Path(log_path)
    check = verify_log(log_path)
    if not check.ok:
        return fail(f"The log chain is broken: {check.error}")
    if check.records < count:
        return fail(f"The log has {check.records} record(s) but the checkpoint covers {count}: "
                    "the log was truncated or replaced.")
    if hash_at(log_path, count) != doc["head"]:
        return fail(f"Record {count} no longer matches the signed hash: history before this "
                    "checkpoint was rewritten.")
    return CheckpointResult(True, count, created, records_since=check.records - count)


__all__ = [
    "CheckpointResult", "PublicKey", "append_checkpoint", "create_checkpoint",
    "generate_signing_keypair", "hash_at", "load_checkpoints", "load_private_key",
    "load_public_key", "parse_checkpoint", "verify_checkpoint",
]
