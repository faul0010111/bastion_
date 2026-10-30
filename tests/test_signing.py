import json
import stat
import sys

import pytest

from bastion.errors import SigningError
from bastion.eventlog import GENESIS, EventLog, _record_hash
from bastion.signing import (
    append_checkpoint,
    create_checkpoint,
    generate_signing_keypair,
    hash_at,
    load_checkpoints,
    load_private_key,
    load_public_key,
    parse_checkpoint,
    verify_checkpoint,
)

PW = "a long and unique passphrase 123"


@pytest.fixture
def keys(tmp_path, fast_scrypt):
    private, public = tmp_path / "keys" / "sign.json", tmp_path / "keys" / "sign.pub"
    key_id = generate_signing_keypair(private, public, PW, scrypt_params=fast_scrypt)
    return private, public, key_id


@pytest.fixture
def log(tmp_path):
    path = tmp_path / "state" / "events.jsonl"
    elog = EventLog(path)
    for i in range(10):
        elog.append("event", {"type": "modified", "path": f"f{i}.txt"})
    return path


def signed(log, keys):
    private, _, key_id = keys
    key, _ = load_private_key(private, PW)
    return create_checkpoint(log, key, key_id)


def rebuild_chain(path, mutate):
    """What a skilled attacker with write access would do: edit and recompute every hash."""
    records = [json.loads(line) for line in path.read_text().splitlines()]
    mutate(records)
    prev, lines = GENESIS, []
    for r in records:
        r["prev"] = prev
        r["hash"] = _record_hash(prev, r["seq"], r["ts"], r["kind"], r["data"])
        prev = r["hash"]
        lines.append(json.dumps(r, sort_keys=True, separators=(",", ":")))
    path.write_text("\n".join(lines) + "\n")


# --- keys -----------------------------------------------------------------------------------

def test_keypair_roundtrip_and_ids_agree(keys):
    private, public, key_id = keys
    _, loaded_id = load_private_key(private, PW)
    assert loaded_id == key_id == load_public_key(public).key_id


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_private_key_is_0600_and_public_key_is_readable(keys):
    private, public, _ = keys
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    assert stat.S_IMODE(public.stat().st_mode) == 0o644


def test_private_key_file_does_not_contain_the_seed_in_clear(keys):
    import base64

    from cryptography.hazmat.primitives import serialization
    private, public, _ = keys
    key, _ = load_private_key(private, PW)
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    text = private.read_text()
    assert base64.b64encode(seed).decode() not in text and seed.hex() not in text
    assert json.loads(text)["public_key"] == json.loads(public.read_text())["public_key"]


def test_wrong_passphrase_is_rejected(keys):
    with pytest.raises(SigningError, match="Wrong passphrase"):
        load_private_key(keys[0], "another long passphrase!!")


def test_a_data_key_file_cannot_be_used_as_a_signing_key(tmp_path, fast_scrypt):
    from bastion.crypto import generate_keyfile
    data_key = tmp_path / "data-key.json"
    generate_keyfile(data_key, PW, scrypt_params=fast_scrypt)
    with pytest.raises(SigningError):          # different AAD: domain separation
        load_private_key(data_key, PW)


def test_keygen_never_overwrites(keys, fast_scrypt):
    private, public, _ = keys
    before = private.read_bytes()
    with pytest.raises(Exception, match="never overwrites"):
        generate_signing_keypair(private, private.with_name("other.pub"), PW, scrypt_params=fast_scrypt)
    with pytest.raises(SigningError, match="never overwrites"):
        generate_signing_keypair(private.with_name("new.json"), public, PW, scrypt_params=fast_scrypt)
    assert not private.with_name("new.json").exists()      # no half-created pair
    assert private.read_bytes() == before


def test_keygen_rejects_weak_passphrase_and_same_path(tmp_path, fast_scrypt):
    with pytest.raises(Exception, match="at least"):
        generate_signing_keypair(tmp_path / "a", tmp_path / "b", "short", scrypt_params=fast_scrypt)
    with pytest.raises(SigningError, match="different"):
        generate_signing_keypair(tmp_path / "a", tmp_path / "a", PW, scrypt_params=fast_scrypt)


def test_tampered_public_key_file_is_rejected(keys):
    _, public, _ = keys
    doc = json.loads(public.read_text())
    doc["key_id"] = "00" * 16
    public.write_text(json.dumps(doc))
    with pytest.raises(SigningError, match="inconsistent"):
        load_public_key(public)


# --- checkpoints ---------------------------------------------------------------------------

def test_checkpoint_verifies_and_survives_log_growth(log, keys):
    cp = signed(log, keys)
    public = load_public_key(keys[1])
    assert verify_checkpoint(log, cp, public).ok
    EventLog(log).append("alert", {"rule": "x"})
    result = verify_checkpoint(log, cp, public)
    assert result.ok and result.records == 10 and result.records_since == 1


def test_forged_or_edited_checkpoint_fails_signature(log, keys):
    cp = signed(log, keys)
    public = load_public_key(keys[1])
    for field, value in (("records", 5), ("head", "f" * 64), ("created_at", "2000-01-01T00:00:00+00:00")):
        forged = dict(cp, **{field: value})
        res = verify_checkpoint(log, forged, public)
        assert not res.ok and "INVALID" in res.error


def test_checkpoint_signed_by_another_key_is_refused(log, keys, tmp_path, fast_scrypt):
    cp = signed(log, keys)
    generate_signing_keypair(tmp_path / "o.json", tmp_path / "o.pub", PW, scrypt_params=fast_scrypt)
    res = verify_checkpoint(log, cp, load_public_key(tmp_path / "o.pub"))
    assert not res.ok and "not by the given public key" in res.error


def test_attacker_who_rebuilds_the_whole_chain_is_still_caught(log, keys):
    cp = signed(log, keys)
    public = load_public_key(keys[1])

    def rewrite(records):
        records[3]["data"]["path"] = "innocent.txt"

    rebuild_chain(log, rewrite)
    from bastion.eventlog import verify_log
    assert verify_log(log).ok                         # the chain alone is fooled...
    res = verify_checkpoint(log, cp, public)
    assert not res.ok and "rewritten" in res.error    # ...the signed checkpoint is not


def test_truncated_log_is_detected(log, keys):
    cp = signed(log, keys)
    lines = log.read_text().splitlines()
    log.write_text("\n".join(lines[:6]) + "\n")
    res = verify_checkpoint(log, cp, load_public_key(keys[1]))
    assert not res.ok and "truncated" in res.error


def test_internally_edited_log_is_reported_as_broken_chain(log, keys):
    cp = signed(log, keys)
    lines = log.read_text().splitlines()
    rec = json.loads(lines[2])
    rec["data"]["path"] = "x"
    lines[2] = json.dumps(rec)
    log.write_text("\n".join(lines) + "\n")
    res = verify_checkpoint(log, cp, load_public_key(keys[1]))
    assert not res.ok and "chain is broken" in res.error


def test_refuses_to_sign_empty_or_broken_log(tmp_path, keys, log):
    private, _, key_id = keys
    key, _ = load_private_key(private, PW)
    with pytest.raises(SigningError, match="empty"):
        create_checkpoint(tmp_path / "missing.jsonl", key, key_id)
    lines = log.read_text().splitlines()
    log.write_text("\n".join(lines[:3] + lines[4:]) + "\n")
    with pytest.raises(SigningError, match="does not verify"):
        create_checkpoint(log, key, key_id)


def test_note_is_signed_too(log, keys):
    private, _, key_id = keys
    key, _ = load_private_key(private, PW)
    cp = create_checkpoint(log, key, key_id, note="weekly")
    assert cp["note"] == "weekly"
    cp["note"] = "edited"
    assert not verify_checkpoint(log, cp, load_public_key(keys[1])).ok


def test_hash_at(log):
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert hash_at(log, 4) == records[3]["hash"] and hash_at(log, 99) is None


# --- parsing and storage -------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "not json", "[]", "{}", '{"type": "other"}',
    json.dumps({"type": "bastion-log-checkpoint", "version": 2}),
    json.dumps({"type": "bastion-log-checkpoint", "version": 1, "records": 0, "head": "a" * 64,
                "key_id": "k", "signature": "s"}),
    json.dumps({"type": "bastion-log-checkpoint", "version": 1, "records": True, "head": "a" * 64,
                "key_id": "k", "signature": "s"}),
    json.dumps({"type": "bastion-log-checkpoint", "version": 1, "records": 3, "head": "XYZ",
                "key_id": "k", "signature": "s"}),
    json.dumps({"type": "bastion-log-checkpoint", "version": 1, "records": 3, "head": "a" * 64}),
    "x" * 70_000,
])
def test_malformed_checkpoints_are_rejected(text):
    with pytest.raises(SigningError):
        parse_checkpoint(text)


def test_load_checkpoints_accepts_pretty_json_and_json_lines(log, keys, tmp_path):
    cp = signed(log, keys)
    pretty = tmp_path / "pretty.json"
    pretty.write_text(json.dumps(cp, indent=2))
    assert load_checkpoints(pretty) == [cp]
    store = tmp_path / "store.jsonl"
    append_checkpoint(store, cp)
    append_checkpoint(store, cp)
    assert load_checkpoints(store) == [cp, cp]
    with pytest.raises(SigningError, match="empty"):
        (tmp_path / "e").write_text("  \n")
        load_checkpoints(tmp_path / "e")
    with pytest.raises(SigningError, match="not found"):
        load_checkpoints(tmp_path / "nope")
