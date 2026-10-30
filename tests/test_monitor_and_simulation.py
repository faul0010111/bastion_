import os
import sys

import pytest

from bastion.canary import canary_events, deploy_canaries
from bastion.config import RulesConfig
from bastion.errors import BastionError
from bastion.eventlog import EventLog, query_records, verify_log
from bastion.inventory import scan_directory
from bastion.monitor import EventProcessor, index_from_inventory
from bastion.rules import RuleEngine
from bastion.simulation import Sandbox, run_simulation
from conftest import noise

CANARY = "000-confidential-finance.txt"


def make_processor(root, tmp_path, canaries=()):
    config = RulesConfig.default()
    index = index_from_inventory(scan_directory(root, config.ignore_patterns))
    log = EventLog(tmp_path / "state" / "events.jsonl")
    proc = EventProcessor(root, RuleEngine(config, canaries), config, log, index)
    return proc, log


def test_processor_records_events_with_hash_and_entropy(make_files, tmp_path):
    d = make_files(3)
    proc, log = make_processor(d, tmp_path)
    (d / "new.txt").write_text("freshly created " * 50)
    created = proc.handle("created", str(d / "new.txt"))
    assert created.type == "created" and len(created.sha256) == 64 and created.entropy > 0
    (d / "f00.txt").write_text("different content " * 40)
    mod = proc.handle("modified", str(d / "f00.txt"))
    assert mod.type == "modified" and mod.prev_entropy is not None
    (d / "f01.txt").rename(d / "f01_renamed.txt")
    moved = proc.handle("moved", str(d / "f01.txt"), str(d / "f01_renamed.txt"))
    assert moved.type == "moved" and moved.dest_path == "f01_renamed.txt"
    (d / "f02.txt").unlink()
    assert proc.handle("deleted", str(d / "f02.txt")).type == "deleted"
    assert [r["data"]["type"] for r in query_records(log.path, kind="event")] == [
        "created", "modified", "moved", "deleted"]
    assert verify_log(log.path).ok


def test_duplicate_modified_without_content_change_is_dropped(make_files, tmp_path):
    d = make_files(1)
    proc, log = make_processor(d, tmp_path)
    assert proc.handle("modified", str(d / "f00.txt")) is None
    assert query_records(log.path, kind="event") == []


def test_temp_file_save_pattern_becomes_a_modification(make_files, tmp_path):
    d = make_files(1)
    proc, _ = make_processor(d, tmp_path)
    tmp = d / "f00.txt.tmp"
    tmp.write_text("new version saved by the editor " * 30)
    assert proc.handle("created", str(tmp)) is None            # ignored
    tmp.replace(d / "f00.txt")
    ev = proc.handle("moved", str(tmp), str(d / "f00.txt"))
    assert ev.type == "modified" and ev.path == "f00.txt"


def test_file_removed_before_read_is_recorded_not_crashed(make_files, tmp_path):
    d = make_files(1)
    proc, _ = make_processor(d, tmp_path)
    ev = proc.handle("modified", str(d / "vanished.txt"))
    assert ev.type == "modified" and "removed" in ev.note and ev.sha256 is None


@pytest.mark.skipif(sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="permissions do not apply to root/Windows")
def test_unreadable_file_is_recorded_with_note(make_files, tmp_path):
    d = make_files(1)
    proc, _ = make_processor(d, tmp_path)
    secret = d / "locked.txt"
    secret.write_text("x")
    secret.chmod(0)
    try:
        ev = proc.handle("created", str(secret))
    finally:
        secret.chmod(0o600)
    assert "permission" in ev.note


def test_events_outside_root_are_ignored(make_files, tmp_path):
    d = make_files(1)
    proc, _ = make_processor(d, tmp_path)
    assert proc.handle("modified", str(tmp_path / "outside.txt")) is None


def test_entropy_spike_on_real_files(make_files, tmp_path):
    d = make_files(20, size=3000)
    proc, log = make_processor(d, tmp_path)
    for i in range(10):
        (d / f"f{i:02d}.txt").write_bytes(noise())
        proc.handle("modified", str(d / f"f{i:02d}.txt"))
    assert "entropy_spike" in {a.rule for a in proc.alerts}
    alert = next(a for a in proc.alerts if a.rule == "entropy_spike")
    assert alert.events and alert.events[0]["entropy"] > 7.5 and alert.events[0]["prev_entropy"] < 6
    assert query_records(log.path, kind="alert") and verify_log(log.path).ok


def test_canary_touch_on_real_files(make_files, tmp_path):
    d = make_files(3)
    deploy_canaries(d, tmp_path / "canaries.json")
    proc, _ = make_processor(d, tmp_path, canaries={CANARY})
    (d / CANARY).write_text("changed")
    proc.handle("modified", str(d / CANARY))
    assert [a.rule for a in proc.alerts] == ["canary_touched"]


def test_canary_deploy_never_overwrites(make_files, tmp_path):
    d = make_files(1)
    (d / CANARY).write_text("the user's real file")
    with pytest.raises(BastionError, match="does not overwrite"):
        deploy_canaries(d, tmp_path / "canaries.json")
    assert (d / CANARY).read_text() == "the user's real file"
    assert not (d / "zzz-client-contracts.txt").exists()


def test_canary_events_for_verification_flow():
    hashes = {"a.txt": "aaa", "b.txt": "bbb", "c.txt": "ccc"}
    current = {"a.txt": "aaa", "b.txt": "changed"}       # a intact, b changed, c vanished
    evs = canary_events(hashes, current, already=set(), now=1.0)
    assert [(e.type, e.path) for e in evs] == [("modified", "b.txt"), ("deleted", "c.txt")]
    assert canary_events(hashes, current, already={"b.txt", "c.txt"}, now=1.0) == []  # no duplicates


# --- simulation -------------------------------------------------------------------

def test_sandbox_refuses_anything_outside_or_not_owned(tmp_path):
    area = tmp_path / "sim" / "data"
    area.mkdir(parents=True)
    box = Sandbox(area)
    real = tmp_path / "real_data.txt"
    real.write_text("DO NOT TOUCH")
    box.create("mine.txt", b"fictional")
    with pytest.raises(BastionError):
        box.overwrite_with_noise("../../real_data.txt")
    with pytest.raises(BastionError):
        box.delete("../../real_data.txt")
    with pytest.raises(BastionError):
        box.rename("mine.txt", "../../escaped.txt")
    (area / "existing.txt").write_text("not created by the simulation")
    with pytest.raises(BastionError, match="was not created"):
        box.delete("existing.txt")
    assert real.read_text() == "DO NOT TOUCH" and (area / "existing.txt").exists()


@pytest.mark.integration
def test_full_simulation_is_safe_and_triggers_expected_rules(tmp_path):
    sentinel = tmp_path / "real_data.txt"
    sentinel.write_text("the user's real data")
    base = tmp_path / "sim"
    report = run_simulation(base, keep=False, seed=7)
    assert {"entropy_spike", "mass_modification", "mass_rename", "mass_deletion",
            "canary_touched", "header_lost", "uniform_extension",
            "note_dropped"} <= report.rules_triggered
    assert report.log_check.ok and report.log_check.records > 50
    assert report.removed and not report.run_dir.exists()          # cleaned up what it created
    assert sentinel.read_text() == "the user's real data"          # nothing outside the sandbox changed
    assert list(base.iterdir()) == []                              # and nothing else was left behind


@pytest.mark.integration
def test_simulation_keep_leaves_inspectable_evidence(tmp_path):
    report = run_simulation(tmp_path / "sim", keep=True, seed=3)
    assert report.kept and (report.run_dir / "state" / "events.jsonl").exists()
    assert verify_log(report.run_dir / "state" / "events.jsonl").ok
