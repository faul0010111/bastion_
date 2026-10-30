"""Property-based tests: invariants that must hold for *any* input, not just the examples."""

import contextlib
import tempfile
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from bastion.config import RulesConfig
from bastion.crypto import DataKey, decrypt_bytes, encrypt_bytes
from bastion.errors import ConfigError, CryptoError, PathValidationError
from bastion.eventlog import EventLog, verify_log
from bastion.inventory import FileEntry, Inventory, compare_inventories
from bastion.paths import is_ignored, is_within, safe_relative_join

FAST = settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])

json_scalars = st.none() | st.booleans() | st.integers(-10 ** 6, 10 ** 6) | st.floats(allow_nan=False, allow_infinity=False) | st.text(max_size=20)
json_values = st.recursive(json_scalars, lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text(max_size=8), c, max_size=4), max_leaves=12)


# --- event log -------------------------------------------------------------------------------

@FAST
@given(st.lists(st.dictionaries(st.text(min_size=1, max_size=6), json_values, max_size=4), min_size=1, max_size=15))
def test_any_sequence_of_records_verifies_and_survives_reopen(tmp_path_factory, payloads):
    path = tmp_path_factory.mktemp("log") / "events.jsonl"
    log = EventLog(path)
    for payload in payloads:
        log.append("event", payload)
    result = verify_log(path)
    assert result.ok and result.records == len(payloads) and result.head == log.head
    assert EventLog(path).head == log.head


@FAST
@given(st.integers(0, 10 ** 6), st.integers(1, 255))
def test_flipping_any_byte_of_the_log_is_detected(tmp_path_factory, position, xor):
    path = tmp_path_factory.mktemp("log") / "events.jsonl"
    log = EventLog(path)
    for i in range(6):
        # Fixed timestamps keep the file identical between runs. With time.time() the last decimal
        # digit of a float can change without changing the parsed value (below double precision),
        # which would be a meaningless flip and made this test flaky.
        log.append("event", {"type": "modified", "path": f"dir/file{i}.txt", "n": i}, ts=1_700_000_000.0 + i)
    original = path.read_bytes()
    index = position % len(original)
    changed = bytearray(original)
    changed[index] ^= xor
    path.write_bytes(bytes(changed))
    result = verify_log(path)                       # must never raise, whatever the damage
    # Two byte changes alter no record and therefore may pass: "\n" -> "\r" (Python's text mode
    # treats both as a line break) and the file's final newline becoming other whitespace.
    newline_to_cr = original[index] == 0x0A and changed[index] == 0x0D
    trailing_blank = index == len(original) - 1 and bytes([changed[index]]).isspace()
    harmless = newline_to_cr or trailing_blank
    assert (not result.ok) or harmless


# --- paths ------------------------------------------------------------------------------------

@FAST
@given(st.text(max_size=40))
def test_safe_relative_join_never_escapes_the_base(rel):
    base = Path(tempfile.gettempdir()).resolve() / "bastion-prop-base"
    try:
        joined = safe_relative_join(base, rel)
    except PathValidationError:
        return
    assert is_within(joined, base) and joined != base


@FAST
@given(st.lists(st.sampled_from(["a", "b", "..", ".", "c.txt", "", "x y"]), max_size=6))
def test_dotdot_segments_are_never_accepted_to_climb_out(parts):
    rel = "/".join(parts)
    base = Path(tempfile.gettempdir()).resolve() / "bastion-prop-base"
    try:
        joined = safe_relative_join(base, rel)
    except PathValidationError:
        return
    assert is_within(joined, base)


@FAST
@given(st.text(alphabet="abc./~$*", max_size=20))
def test_is_ignored_never_raises(path):
    assert isinstance(is_ignored(path, ["*.swp", "~$*", ".DS_Store"]), bool)


# --- crypto -----------------------------------------------------------------------------------

KEY = DataKey(bytes(range(16)), bytes(range(32)))


@FAST
@given(st.binary(max_size=4096))
def test_encrypt_decrypt_roundtrip_for_any_bytes(data):
    blob = encrypt_bytes(KEY, data)
    assert decrypt_bytes(KEY, blob) == data
    if len(data) >= 8:                  # shorter inputs could match the header bytes by coincidence
        assert data not in blob


@FAST
@given(st.binary(min_size=1, max_size=512), st.integers(0, 10 ** 6), st.integers(1, 255))
def test_any_single_byte_change_to_the_blob_is_rejected(data, position, xor):
    blob = bytearray(encrypt_bytes(KEY, data))
    blob[position % len(blob)] ^= xor
    with pytest.raises(CryptoError):
        decrypt_bytes(KEY, bytes(blob))


@FAST
@given(st.binary(max_size=64))
def test_decrypt_never_raises_anything_but_cryptoerror(junk):
    with pytest.raises(CryptoError):
        decrypt_bytes(KEY, junk)


# --- inventory diff ---------------------------------------------------------------------------

names = st.sampled_from([f"{d}/{n}.{e}" for d in ("a", "b") for n in ("x", "y", "z") for e in ("txt", "docx", "locked")])
inventories = st.dictionaries(names, st.sampled_from(["h1", "h2", "h3", "h4"]), max_size=12)


def make_inventory(mapping):
    inv = Inventory(root="/r", created_at=0.0)
    for path, sha in mapping.items():
        inv.entries[path] = FileEntry(path, 10, 0, sha, 4.0)
    return inv


@FAST
@given(inventories, inventories)
def test_diff_accounts_for_every_path_exactly_once(old_map, new_map):
    old, new = make_inventory(old_map), make_inventory(new_map)
    diff = compare_inventories(old, new)
    old_seen = (list(diff.removed) + [s for s, _ in diff.renamed] + [s for s, _ in diff.renamed_changed]
                + diff.modified)
    new_seen = (list(diff.added) + [d for _, d in diff.renamed] + [d for _, d in diff.renamed_changed]
                + diff.modified)
    unchanged_old = set(old.entries) - set(old_seen)
    unchanged_new = set(new.entries) - set(new_seen)
    assert len(old_seen) == len(set(old_seen)) and len(new_seen) == len(set(new_seen))
    assert unchanged_old == unchanged_new and len(unchanged_old) == diff.unchanged
    for path in unchanged_old:
        assert old.entries[path].sha256 == new.entries[path].sha256


@FAST
@given(inventories)
def test_diff_of_identical_inventories_is_clean(mapping):
    diff = compare_inventories(make_inventory(mapping), make_inventory(mapping))
    assert diff.is_clean and diff.unchanged == len(mapping)


@FAST
@given(inventories, inventories)
def test_root_hash_is_order_independent_and_content_sensitive(a, b):
    inv_a = make_inventory(a)
    shuffled = make_inventory(dict(reversed(list(a.items()))))
    assert inv_a.root_hash() == shuffled.root_hash()
    assert (inv_a.root_hash() == make_inventory(b).root_hash()) == (a == b)


# --- configuration ------------------------------------------------------------------------------

@FAST
@given(json_values)
def test_config_parser_only_ever_raises_configerror(data):
    with contextlib.suppress(ConfigError):
        RulesConfig.from_dict(data)


@FAST
@given(st.dictionaries(st.sampled_from(["mass_modification", "header_lost", "note_dropped", "entropy_spike"]),
                       st.dictionaries(st.sampled_from(["enabled", "threshold", "window_seconds", "min_entropy",
                                                        "min_size_bytes", "max_size_bytes", "min_delta", "bogus"]),
                                       json_scalars, max_size=4), max_size=4))
def test_rule_settings_parser_only_ever_raises_configerror(rules):
    try:
        cfg = RulesConfig.from_dict({"rules": rules})
    except ConfigError:
        return
    assert RulesConfig.from_dict(cfg.to_dict()) == cfg          # whatever is accepted round-trips
    for settings_ in cfg.rules.values():
        assert settings_.threshold >= 1 and settings_.window_seconds > 0
