import dataclasses

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from bastion.config import (
    HeaderSettings,
    NoteSettings,
    RulesConfig,
    RuleSettings,
    load_config,
)
from bastion.errors import ConfigError
from bastion.rules import RuleEngine
from conftest import ev

SHA = "ab" * 32


def cfg(**overrides):
    base = RulesConfig.default()
    rules = dict(base.rules)
    rules.update(overrides)
    return dataclasses.replace(base, rules=rules)


def rules_of(alerts):
    return [a.rule for a in alerts]


def lost(i, ts=None, **kw):
    fields = dict(size=5000, entropy=7.99, prev_entropy=7.97, magic="unknown", prev_magic="zip")
    fields.update(kw)
    return ev("modified", f"contract{i}.docx", ts=i if ts is None else ts, **fields)


# --- header_lost ---------------------------------------------------------------------

def test_header_lost_catches_encrypted_office_files_that_entropy_cannot_see():
    engine = RuleEngine(cfg(header_lost=HeaderSettings(True, 4, 15.0)))
    alerts = []
    for i in range(4):
        alerts += engine.process(lost(i))
    assert rules_of(alerts) == ["header_lost"]
    assert "entropy_spike" not in rules_of(alerts)       # prev entropy was already ~8
    assert alerts[0].severity == "high" and alerts[0].observed == 4


@pytest.mark.parametrize("override", [
    dict(prev_magic="text"),            # plain text has no header to lose
    dict(prev_magic=""),                # baseline created by an older Bastion
    dict(prev_magic=None),
    dict(magic="zip"),                  # header intact
    dict(magic="pdf"),                  # converted to another known format
    dict(entropy=3.0),                  # not high entropy: probably just a different text/binary file
    dict(size=100),                     # too small to judge
])
def test_header_lost_ignores_benign_shapes(override):
    engine = RuleEngine(cfg(header_lost=HeaderSettings(True, 3, 15.0)))
    alerts = []
    for i in range(10):
        alerts += engine.process(lost(i, **override))
    assert "header_lost" not in rules_of(alerts)


def test_header_lost_applies_to_renames_with_new_content():
    engine = RuleEngine(cfg(header_lost=HeaderSettings(True, 3, 15.0)))
    alerts = []
    for i in range(3):
        alerts += engine.process(ev("moved", f"a{i}.pdf", ts=i, dest_path=f"a{i}.pdf.enc", size=4000,
                                    entropy=7.99, magic="unknown", prev_magic="pdf"))
    assert "header_lost" in rules_of(alerts)


def test_header_lost_window_expires():
    engine = RuleEngine(cfg(header_lost=HeaderSettings(True, 3, 10.0)))
    alerts = []
    for i in range(6):
        alerts += engine.process(lost(i, ts=i * 30))     # one every 30 s: never 3 within 10 s
    assert "header_lost" not in rules_of(alerts)


# --- uniform_extension -----------------------------------------------------------------

def moved(i, new_ext, ts=None, old="docx"):
    return ev("moved", f"file{i}.{old}", ts=i if ts is None else ts, dest_path=f"file{i}.{old}.{new_ext}")


def test_uniform_extension_names_the_shared_extension():
    engine = RuleEngine(cfg(uniform_extension=RuleSettings(True, 5, 15.0)))
    alerts = []
    for i in range(5):
        alerts += engine.process(moved(i, "locked"))
    hit = [a for a in alerts if a.rule == "uniform_extension"]
    assert len(hit) == 1 and ".locked" in hit[0].explanation and hit[0].observed == 5


def test_uniform_extension_needs_the_same_extension():
    engine = RuleEngine(cfg(uniform_extension=RuleSettings(True, 5, 15.0)))
    alerts = []
    for i in range(10):
        alerts += engine.process(moved(i, f"ext{i % 3}"))      # three different extensions, ~3 each
    assert "uniform_extension" not in rules_of(alerts)


def test_uniform_extension_ignores_renames_that_keep_the_extension():
    engine = RuleEngine(cfg(uniform_extension=RuleSettings(True, 3, 15.0)))
    alerts = []
    for i in range(10):
        alerts += engine.process(ev("moved", f"a{i}.txt", ts=i, dest_path=f"b{i}.txt"))
        alerts += engine.process(ev("moved", f"c{i}.txt", ts=i, dest_path=f"c{i}"))   # extension removed
    assert "uniform_extension" not in rules_of(alerts)


def test_uniform_extension_counts_distinct_files():
    engine = RuleEngine(cfg(uniform_extension=RuleSettings(True, 3, 15.0)))
    alerts = []
    for _ in range(10):                        # the same file flapping must not look like many files
        alerts += engine.process(ev("moved", "same.docx", ts=0.0, dest_path="same.docx.locked"))
    assert "uniform_extension" not in rules_of(alerts)


# --- note_dropped ------------------------------------------------------------------------

def note(folder, ts=0.0, sha=SHA, size=300, name="NOTE.txt"):
    return ev("created", f"{folder}/{name}", ts=ts, sha256=sha, size=size)


def test_note_dropped_fires_for_identical_file_in_many_folders():
    engine = RuleEngine(cfg(note_dropped=NoteSettings(True, 4, 30.0)))
    alerts = []
    for i in range(4):
        alerts += engine.process(note(f"dept{i}", ts=i))
    hit = [a for a in alerts if a.rule == "note_dropped"]
    assert len(hit) == 1 and hit[0].observed == 4 and "NOTE.txt" in hit[0].explanation


def test_note_dropped_ignores_many_files_in_one_folder():
    engine = RuleEngine(cfg(note_dropped=NoteSettings(True, 3, 30.0)))
    alerts = []
    for i in range(10):
        alerts += engine.process(note("same", ts=i, name=f"n{i}.txt"))
    assert "note_dropped" not in rules_of(alerts)


def test_note_dropped_ignores_different_contents():
    engine = RuleEngine(cfg(note_dropped=NoteSettings(True, 3, 30.0)))
    alerts = []
    for i in range(10):
        alerts += engine.process(note(f"d{i}", ts=i, sha=f"{i:064x}"))
    assert "note_dropped" not in rules_of(alerts)


@pytest.mark.parametrize("size", [0, 10, 70_000])
def test_note_dropped_ignores_empty_tiny_and_large_files(size):
    engine = RuleEngine(cfg(note_dropped=NoteSettings(True, 3, 30.0)))
    alerts = []
    for i in range(10):
        alerts += engine.process(note(f"d{i}", ts=i, size=size))
    assert "note_dropped" not in rules_of(alerts)


def test_note_dropped_only_counts_creations():
    engine = RuleEngine(cfg(note_dropped=NoteSettings(True, 3, 30.0)))
    alerts = []
    for i in range(10):
        alerts += engine.process(ev("modified", f"d{i}/NOTE.txt", ts=i, sha256=SHA, size=300))
    assert "note_dropped" not in rules_of(alerts)


def test_grouped_windows_are_pruned_so_memory_stays_bounded():
    engine = RuleEngine(RulesConfig.default())
    for i in range(500):                                   # 500 different one-off extensions
        engine.process(moved(i, f"x{i}", ts=i * 100.0))
    assert len(engine._grouped["uniform_extension"]) <= 1


def test_grouped_rules_respect_cooldown():
    engine = RuleEngine(cfg(uniform_extension=RuleSettings(True, 3, 100.0)))
    alerts = []
    for i in range(30):
        alerts += engine.process(moved(i, "locked", ts=i))
    assert rules_of(alerts).count("uniform_extension") == 1     # default cooldown is 30 s


def test_new_rules_feed_correlation():
    engine = RuleEngine(RulesConfig.default())
    alerts = []
    for i in range(6):
        alerts += engine.process(lost(i, ts=i))
        alerts += engine.process(moved(i, "locked", ts=i))
    for i in range(5):
        alerts += engine.process(note(f"d{i}", ts=i))
    assert {"header_lost", "uniform_extension", "note_dropped", "correlated_signals"} <= set(rules_of(alerts))


# --- configuration -------------------------------------------------------------------------

def test_default_config_roundtrips_through_json_dict():
    default = RulesConfig.default()
    assert RulesConfig.from_dict(default.to_dict()) == default


def test_new_rules_are_configurable():
    parsed = RulesConfig.from_dict({"rules": {
        "header_lost": {"threshold": 3, "min_entropy": 6.5, "min_size_bytes": 100},
        "note_dropped": {"enabled": False, "max_size_bytes": 1000},
        "uniform_extension": {"threshold": 4},
    }})
    header, notes = parsed.rules["header_lost"], parsed.rules["note_dropped"]
    assert (header.threshold, header.min_entropy, header.min_size_bytes) == (3, 6.5, 100)
    assert notes.enabled is False and notes.max_size_bytes == 1000
    assert parsed.rules["uniform_extension"].threshold == 4


@pytest.mark.parametrize("rules", [
    {"header_lost": {"min_delta": 1}},                 # belongs to entropy_spike
    {"note_dropped": {"min_entropy": 5}},
    {"uniform_extension": {"min_size_bytes": 5}},
    {"header_lost": {"min_entropy": 9}},               # out of range
    {"note_dropped": {"max_size_bytes": -1}},
    {"header_lost": {"threshold": 0}},
])
def test_invalid_settings_for_new_rules_are_rejected(rules):
    with pytest.raises(ConfigError):
        RulesConfig.from_dict({"rules": rules})


def test_example_rules_file_loads(tmp_path):
    import json
    from pathlib import Path
    example = Path(__file__).resolve().parent.parent / "examples" / "rules.example.json"
    config = load_config(example)
    assert set(config.rules) >= {"header_lost", "uniform_extension", "note_dropped"}
    json.loads(example.read_text())


# --- properties -------------------------------------------------------------------------------

_events = st.lists(
    st.tuples(
        st.sampled_from(["created", "modified", "moved", "deleted"]),
        st.integers(0, 6),                      # file number
        st.integers(0, 3),                      # folder number
        st.sampled_from(["", "locked", "txt", "pdf"]),
        st.sampled_from(["zip", "pdf", "text", "unknown", ""]),
        st.floats(0, 8),
        st.integers(0, 80_000),
        st.floats(0, 5),                        # time step
    ),
    max_size=120,
)


@settings(max_examples=60, deadline=None)
@given(_events)
def test_engine_never_raises_and_alerts_are_well_formed(items):
    engine = RuleEngine(RulesConfig.default())
    ts = 0.0
    for kind, n, folder, ext, magic, entropy, size, step in items:
        ts += step
        path = f"d{folder}/f{n}.txt"
        dest = f"d{folder}/f{n}.{ext}" if kind == "moved" and ext else None
        event = ev(kind, path, ts=ts, dest_path=dest, sha256=SHA if kind == "created" else None,
                   size=size, entropy=entropy, prev_entropy=entropy / 2, magic=magic, prev_magic="zip")
        for alert in engine.process(event):
            assert alert.rule and alert.severity in ("high", "medium", "low")
            assert alert.observed >= alert.threshold or alert.rule == "correlated_signals"
            assert alert.explanation and alert.benign_causes and alert.suggestion


@settings(max_examples=40, deadline=None)
@given(_events)
def test_engine_is_deterministic(items):
    def run():
        engine = RuleEngine(RulesConfig.default())
        out, ts = [], 0.0
        for kind, n, folder, ext, magic, entropy, size, step in items:
            ts += step
            dest = f"d{folder}/f{n}.{ext}" if kind == "moved" and ext else None
            out += [a.rule for a in engine.process(
                ev(kind, f"d{folder}/f{n}.txt", ts=ts, dest_path=dest, sha256=SHA, size=size,
                   entropy=entropy, prev_entropy=0.0, magic=magic, prev_magic="zip"))]
        return out
    assert run() == run()
