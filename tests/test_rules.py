import dataclasses
import json

import pytest

from bastion.config import EntropySettings, RulesConfig, RuleSettings, load_config
from bastion.errors import ConfigError
from bastion.rules import RuleEngine
from conftest import ev


def cfg(**overrides):
    base = RulesConfig.default()
    rules = dict(base.rules)
    for name, settings in overrides.items():
        rules[name] = settings
    return dataclasses.replace(base, rules=rules, cooldown_seconds=30.0)


def rules_of(alerts):
    return [a.rule for a in alerts]


def test_mass_modification_fires_at_threshold_only():
    engine = RuleEngine(cfg(mass_modification=RuleSettings(True, 5, 10.0)))
    alerts = []
    for i in range(4):
        alerts += engine.process(ev("modified", f"a{i}.txt", ts=i))
    assert alerts == []
    alerts = engine.process(ev("modified", "a4.txt", ts=4))
    assert rules_of(alerts) == ["mass_modification"]
    assert alerts[0].observed == 5 and alerts[0].threshold == 5


def test_same_file_repeated_does_not_count_as_many_files():
    engine = RuleEngine(cfg(mass_modification=RuleSettings(True, 3, 10.0)))
    alerts = []
    for i in range(50):
        alerts += engine.process(ev("modified", "same.txt", ts=i * 0.01))
    assert alerts == []


def test_events_outside_window_do_not_accumulate():
    engine = RuleEngine(cfg(mass_modification=RuleSettings(True, 3, 5.0)))
    alerts = []
    for i in range(10):
        alerts += engine.process(ev("modified", f"a{i}.txt", ts=i * 10))  # 10 s apart
    assert alerts == []


def test_cooldown_suppresses_repeats_then_allows_again():
    engine = RuleEngine(cfg(mass_deletion=RuleSettings(True, 2, 10.0)))
    first = engine.process_many([ev("deleted", "a", 0), ev("deleted", "b", 1)])
    assert rules_of(first) == ["mass_deletion"]
    again = engine.process_many([ev("deleted", "c", 2), ev("deleted", "d", 3)])
    assert again == []  # within the 30 s cooldown
    later = engine.process_many([ev("deleted", "e", 100), ev("deleted", "f", 101)])
    assert rules_of(later) == ["mass_deletion"]


def test_mass_rename_and_extension_change():
    engine = RuleEngine(cfg(mass_rename=RuleSettings(True, 3, 10.0),
                            extension_change=RuleSettings(True, 3, 10.0)))
    # renames that keep the extension: only mass_rename
    alerts = engine.process_many([ev("moved", f"a{i}.txt", i, dest_path=f"b{i}.txt") for i in range(3)])
    assert rules_of(alerts) == ["mass_rename"]
    # renames that change the extension: extension_change fires
    engine2 = RuleEngine(cfg(mass_rename=RuleSettings(False, 3, 10.0),
                             extension_change=RuleSettings(True, 3, 10.0)))
    alerts = engine2.process_many([ev("moved", f"a{i}.txt", i, dest_path=f"a{i}.txt.locked") for i in range(3)])
    assert rules_of(alerts) == ["extension_change"]


def test_entropy_spike_needs_big_jump_and_high_value():
    s = EntropySettings(True, 3, 10.0, min_entropy=7.5, min_delta=2.5, min_size_bytes=1024)
    engine = RuleEngine(cfg(entropy_spike=s, mass_modification=RuleSettings(False, 99, 10.0)))
    hits = engine.process_many([
        ev("modified", f"t{i}.txt", i, entropy=7.9, prev_entropy=4.2, size=4096) for i in range(3)])
    assert rules_of(hits) == ["entropy_spike"]


@pytest.mark.parametrize("kwargs", [
    dict(entropy=7.9, prev_entropy=7.8, size=4096),   # was already high (e.g. .zip): no jump
    dict(entropy=6.0, prev_entropy=2.0, size=4096),   # big jump but low final value
    dict(entropy=7.9, prev_entropy=4.0, size=100),    # file too small
    dict(entropy=7.9, prev_entropy=None, size=4096),  # no previous reference
])
def test_entropy_spike_ignores_non_signals(kwargs):
    s = EntropySettings(True, 2, 10.0)
    engine = RuleEngine(cfg(entropy_spike=s))
    assert engine.process_many([ev("modified", f"x{i}", i, **kwargs) for i in range(5)]) == []


def test_created_files_with_high_entropy_are_not_a_signal():
    s = EntropySettings(True, 2, 10.0)
    engine = RuleEngine(cfg(entropy_spike=s))
    assert engine.process_many([ev("created", f"z{i}.zip", i, entropy=7.99, size=9999) for i in range(5)]) == []


def test_canary_fires_immediately_but_not_on_creation():
    engine = RuleEngine(cfg(), canary_paths={"canary.txt"})
    assert engine.process(ev("created", "canary.txt", 0)) == []
    alerts = engine.process(ev("modified", "canary.txt", 1))
    assert rules_of(alerts) == ["canary_touched"] and alerts[0].severity == "high"
    engine2 = RuleEngine(cfg(), canary_paths={"canary.txt"})
    assert rules_of(engine2.process(ev("moved", "canary.txt", 1, dest_path="canary.txt.x"))) == ["canary_touched"]
    engine3 = RuleEngine(cfg(), canary_paths={"canary.txt"})
    assert rules_of(engine3.process(ev("deleted", "canary.txt", 1))) == ["canary_touched"]


def test_correlated_signals_when_three_distinct_rules_fire():
    engine = RuleEngine(cfg(
        mass_modification=RuleSettings(True, 2, 10.0),
        mass_deletion=RuleSettings(True, 2, 10.0),
        mass_rename=RuleSettings(True, 2, 10.0),
    ), canary_paths=set())
    alerts = engine.process_many([
        ev("modified", "a", 0), ev("modified", "b", 0.1),
        ev("deleted", "c", 0.2), ev("deleted", "d", 0.3),
        ev("moved", "e", 0.4, dest_path="e2"), ev("moved", "f", 0.5, dest_path="f2"),
    ])
    assert rules_of(alerts)[-1] == "correlated_signals"
    assert set(rules_of(alerts)) >= {"mass_modification", "mass_deletion", "mass_rename"}


def test_disabled_rule_never_fires():
    engine = RuleEngine(cfg(mass_deletion=RuleSettings(False, 1, 10.0)))
    assert engine.process_many([ev("deleted", f"a{i}", i) for i in range(20)]) == []


def test_alert_is_hedged_and_explains_itself():
    engine = RuleEngine(cfg(mass_deletion=RuleSettings(True, 2, 10.0)))
    alert = engine.process_many([ev("deleted", "a", 0), ev("deleted", "b", 1)])[0].to_dict()
    assert alert["benign_causes"] and alert["suggestion"] and alert["events"]
    assert "does not prove" in alert["disclaimer"]
    text = json.dumps(alert).lower()
    for forbidden in ("ransomware detected", "is malware", "attack confirmed"):
        assert forbidden not in text


def test_related_events_are_capped_but_total_is_reported():
    engine = RuleEngine(cfg(mass_deletion=RuleSettings(True, 2, 100.0)))
    alerts = engine.process_many([ev("deleted", f"f{i}", i * 0.001) for i in range(2)])
    assert alerts[0].total_related == 2
    engine = RuleEngine(cfg(mass_deletion=RuleSettings(True, 50, 100.0)))
    alert = engine.process_many([ev("deleted", f"f{i}", i * 0.001) for i in range(50)])[0]
    assert len(alert.events) == 20 and alert.total_related == 50


# --- configuration -------------------------------------------------------------

def test_config_rejects_unknown_keys_and_bad_values(tmp_path):
    for bad in (
        {"rules": {"nonexistent_rule": {}}},
        {"rules": {"mass_rename": {"threshold": 0}}},
        {"rules": {"mass_rename": {"threshold": "ten"}}},
        {"rules": {"mass_rename": {"enabled": "yes"}}},
        {"rules": {"mass_rename": {"limit": 3}}},
        {"rules": {"mass_rename": {"min_entropy": 5}}},  # only valid for entropy_spike
        {"cooldown_seconds": -1},
        {"ignore_patterns": "*.tmp"},
        [],
    ):
        with pytest.raises(ConfigError):
            RulesConfig.from_dict(bad)
    p = tmp_path / "r.json"
    p.write_text("{ not json")
    with pytest.raises(ConfigError):
        load_config(p)
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.json")


def test_config_override_and_defaults_roundtrip():
    c = RulesConfig.from_dict({"rules": {"mass_rename": {"threshold": 3}, "entropy_spike": {"min_delta": 1.5}}})
    assert c.rules["mass_rename"].threshold == 3
    assert c.rules["entropy_spike"].min_delta == 1.5
    assert c.rules["mass_deletion"].threshold == RulesConfig.default().rules["mass_deletion"].threshold
    assert RulesConfig.from_dict(RulesConfig.default().to_dict()) == RulesConfig.default()
