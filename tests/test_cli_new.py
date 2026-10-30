"""CLI-level tests for the v0.2 commands (status, report, sign, log checkpoint)."""

import json

import pytest

from bastion.cli import main
from bastion.eventlog import EventLog
from bastion.events import Event

PW = "a long and unique passphrase 123"
NOW = 1_800_000_000.0


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("BASTION_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("BASTION_PASSPHRASE", PW)
    monkeypatch.setenv("NO_COLOR", "1")
    return tmp_path


@pytest.fixture
def state(env):
    base = env / "state"
    log = EventLog(base / "events.jsonl")
    log.append("system", {"action": "monitor_start"})
    for i in range(5):
        log.append("event", Event("modified", f"docs/f{i}.txt", NOW + i).to_dict())
    return base


def run(*argv):
    return main([str(a) for a in argv])


def test_status_reports_missing_state(env, capsys):
    assert run("status", "--state", env / "nothing") == 2
    assert "No Bastion state" in capsys.readouterr().err


def test_status_ok_and_json(state, capsys):
    assert run("status", "--state", state) == 0
    assert "Bastion status" in capsys.readouterr().out
    assert run("status", "--state", state, "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is True and data["analysis"]["log"]["records"] == 6


def test_status_fails_on_broken_chain(state, capsys):
    lines = (state / "events.jsonl").read_text().splitlines()
    (state / "events.jsonl").write_text("\n".join(lines[:2] + lines[3:]) + "\n")
    assert run("status", "--state", state) == 1
    assert "BROKEN" in capsys.readouterr().out


def test_report_formats_and_default_location(state, capsys):
    assert run("report", "--state", state) == 0
    written = list((state / "reports").glob("bastion-report-*.html"))
    assert len(written) == 1 and "Bastion incident report" in written[0].read_text()
    assert run("report", "--state", state, "--format", "md", "--output", "-") == 0
    assert "# Bastion incident report" in capsys.readouterr().out
    assert run("report", "--state", state, "--format", "json", "--output", "-") == 0
    assert json.loads(capsys.readouterr().out)["log"]["records"] == 6


def test_report_refuses_to_overwrite_and_to_write_inside_monitored_folder(state, env, capsys):
    target = env / "r.html"
    assert run("report", "--state", state, "--output", target) == 0
    assert run("report", "--state", state, "--output", target) == 2
    monitored = env / "watched"
    monitored.mkdir()
    assert run("report", "--folder", monitored, "--state", state, "--output", monitored / "r.html") == 2
    assert "must not be written inside" in capsys.readouterr().err
    assert not (monitored / "r.html").exists()


def test_report_without_log_is_a_clear_error(env, capsys):
    assert run("report", "--state", env / "empty") == 2
    assert "nothing to report" in capsys.readouterr().err


def test_sign_checkpoint_verify_and_detect_rewrite(state, env, capsys):
    private, public, cp = env / "k" / "s.json", env / "k" / "s.pub", env / "cp.json"
    assert run("sign", "keygen", "--private", private, "--public", public) == 0
    assert run("log", "checkpoint", "--state", state, "--signing-key", private, "--output", cp) == 0
    assert run("log", "verify", "--state", state, "--public-key", public, "--checkpoint", cp) == 0
    assert "OK" in capsys.readouterr().out
    # the checkpoint was also stored next to the log, so the short form works too
    assert run("log", "verify", "--state", state, "--public-key", public) == 0
    assert run("status", "--state", state, "--public-key", public, "--json") == 0

    # rewrite a record and recompute the chain
    from bastion.eventlog import GENESIS, _record_hash
    path = state / "events.jsonl"
    recs = [json.loads(line) for line in path.read_text().splitlines()]
    recs[2]["data"]["path"] = "innocent.txt"
    prev, lines = GENESIS, []
    for r in recs:
        r["prev"], r["hash"] = prev, _record_hash(prev, r["seq"], r["ts"], r["kind"], r["data"])
        prev = r["hash"]
        lines.append(json.dumps(r, sort_keys=True, separators=(",", ":")))
    path.write_text("\n".join(lines) + "\n")
    capsys.readouterr()
    assert run("log", "verify", "--state", state) == 0                      # the chain alone is fooled
    assert run("log", "verify", "--state", state, "--public-key", public, "--checkpoint", cp) == 1
    assert "rewritten" in capsys.readouterr().out
    assert run("status", "--state", state, "--public-key", public) == 1


def test_checkpoint_option_requires_public_key(state, env, capsys):
    cp = env / "cp.json"
    cp.write_text("{}")
    assert run("log", "verify", "--state", state, "--checkpoint", cp) == 2
    assert "needs --public-key" in capsys.readouterr().err


def test_signing_key_inside_monitored_folder_is_refused(state, env, capsys):
    watched = env / "watched"
    watched.mkdir()
    key = watched / "s.json"
    assert run("sign", "keygen", "--private", key, "--public", env / "s.pub") == 0
    assert run("log", "checkpoint", "--folder", watched, "--state", state, "--signing-key", key) == 2
    assert "must not live inside" in capsys.readouterr().err


def test_checkpoint_with_wrong_passphrase(state, env, monkeypatch, capsys):
    private, public = env / "k" / "s.json", env / "k" / "s.pub"
    run("sign", "keygen", "--private", private, "--public", public)
    monkeypatch.setenv("BASTION_PASSPHRASE", "not the right passphrase")
    assert run("log", "checkpoint", "--state", state, "--signing-key", private) == 2
    assert "Wrong passphrase" in capsys.readouterr().err


def test_rules_command_lists_new_rules(capsys):
    assert run("rules") == 0
    rules = json.loads(capsys.readouterr().out)["rules"]
    assert {"header_lost", "uniform_extension", "note_dropped"} <= set(rules)


def test_verify_flags_header_loss_in_files_that_were_already_compressed(env, capsys):
    import os
    import zipfile
    folder, state = env / "office", env / "st"
    folder.mkdir()
    for i in range(8):                      # real ZIP containers, like .docx/.xlsx
        with zipfile.ZipFile(folder / f"contract{i}.docx", "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("word/document.xml", os.urandom(3000))
    assert run("inventory", folder, "--state", state) == 0
    for i in range(8):                      # content replaced by random bytes: entropy was ~8 before too
        (folder / f"contract{i}.docx").write_bytes(os.urandom(4000))
    capsys.readouterr()
    assert run("verify", folder, "--state", state) == 1
    out = capsys.readouterr().out
    assert "header_lost" in out and "entropy_spike" not in out


def test_inventory_written_by_0_1_has_no_type_information_and_never_triggers_header_lost(tmp_path):
    from bastion.inventory import load_inventory, save_inventory, scan_directory
    d = tmp_path / "d"
    d.mkdir()
    (d / "a.txt").write_text("hello " * 100)
    path = tmp_path / "inv.json"
    save_inventory(scan_directory(d), path)
    data = json.loads(path.read_text())
    for item in data["files"]:
        del item["magic"]                   # what a 0.1 inventory looks like (root hash ignores it)
    path.write_text(json.dumps(data))
    loaded = load_inventory(path)
    assert loaded.entries["a.txt"].magic == ""
