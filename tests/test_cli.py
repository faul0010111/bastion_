"""CLI-level tests for the original commands: the wiring users actually touch."""

import io
import json
import os
import sys

import pytest

from bastion import cli
from bastion.cli import main

PW = "a long and unique passphrase 123"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("BASTION_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("BASTION_PASSPHRASE", PW)
    monkeypatch.setenv("BASTION_PASSPHRASE_NEW", PW + " new")
    monkeypatch.setenv("NO_COLOR", "1")
    return tmp_path


@pytest.fixture
def folder(env):
    d = env / "business"
    d.mkdir()
    for i in range(12):
        (d / f"doc{i:02d}.txt").write_text(f"business document number {i} " * 80)
    return d


def run(*argv):
    return main([str(a) for a in argv])


def test_version_and_usage_errors(capsys):
    with pytest.raises(SystemExit) as exc:
        run("--version")
    assert exc.value.code == 0 and "bastion 0.2.0" in capsys.readouterr().out
    with pytest.raises(SystemExit) as exc:
        run("no-such-command")
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        run("events", "--type", "exploded")
    assert exc.value.code == 2


def test_inventory_verify_cycle(folder, env, capsys):
    state = env / "state"
    assert run("inventory", folder, "--state", state) == 0
    assert "Inventory created: 12 files" in capsys.readouterr().out
    assert run("inventory", folder, "--state", state) == 2                  # refuses to replace silently
    assert "--update" in capsys.readouterr().err
    assert run("verify", folder, "--state", state) == 0
    assert "No differences" in capsys.readouterr().out

    (folder / "doc00.txt").write_text("changed")
    (folder / "doc01.txt").unlink()
    (folder / "new.txt").write_text("brand new")
    assert run("verify", folder, "--state", state) == 0                     # below every threshold
    out = capsys.readouterr().out
    assert "Modified (1)" in out and "Removed (1)" in out and "New (1)" in out

    assert run("inventory", folder, "--state", state, "--update") == 0
    assert list(state.glob("inventory-previous-*.json"))                    # old baseline preserved
    assert run("verify", folder, "--state", state) == 0


def test_verify_without_baseline_and_state_inside_folder(folder, env, capsys):
    assert run("verify", folder, "--state", env / "none") == 2
    assert "no baseline" in capsys.readouterr().err.lower()
    assert run("inventory", folder, "--state", folder / "state") == 2
    assert "state directory" in capsys.readouterr().err.lower()


def test_verify_raises_alerts_and_exit_code_1_for_a_burst(folder, env, capsys):
    state = env / "state"
    assert run("canary", "create", folder, "--state", state) == 0
    assert run("inventory", folder, "--state", state) == 0
    for p in folder.glob("doc*.txt"):
        p.rename(p.with_name(p.name + ".locked"))
    (folder / "000-confidential-finance.txt").write_text("touched")
    capsys.readouterr()
    assert run("verify", folder, "--state", state) == 1
    out = capsys.readouterr().out
    assert "canary_touched" in out and "signal(s) for analysis" in out and "uniform_extension" in out


def test_events_filters_and_json(folder, env, capsys):
    state = env / "state"
    run("inventory", folder, "--state", state)
    for p in sorted(folder.glob("doc*.txt")):
        p.rename(p.with_name(p.name + ".locked"))
    run("verify", folder, "--state", state)
    capsys.readouterr()
    assert run("events", "--state", state, "--alerts") == 0
    assert "ALERT[" in capsys.readouterr().out
    assert run("events", "--state", state, "--events-only", "--type", "moved", "--path", "doc03", "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 1 and data[0]["data"]["dest_path"] == "doc03.txt.locked"
    assert run("events", "--state", state, "--rule", "mass_rename", "--since", "1h", "--limit", "5") == 0
    assert run("events", "--state", state, "--path", "nothing-matches-this") == 0
    assert "No records match" in capsys.readouterr().out
    assert run("events", "--state", env / "empty") == 0
    assert "No events recorded" in capsys.readouterr().out
    assert run("events", "--state", state, "--since", "yesterday-ish") == 2


def test_log_verify_with_anchor_and_tampering(folder, env, capsys):
    state = env / "state"
    run("inventory", folder, "--state", state)
    capsys.readouterr()
    assert run("log", "verify", "--state", state) == 0
    head = next(line for line in capsys.readouterr().out.splitlines() if line.startswith("Head hash:")).split()[-1]
    assert run("log", "verify", "--state", state, "--anchor", head) == 0
    assert run("log", "verify", "--state", state, "--anchor", "f" * 64) == 1
    log = state / "events.jsonl"
    log.write_text(log.read_text().replace("inventory_created", "something_else"))
    capsys.readouterr()
    assert run("log", "verify", "--state", state) == 1
    assert "CHAIN BROKEN" in capsys.readouterr().out
    assert run("events", "--state", state) == 0                                # still readable, with a warning
    assert "does not verify" in capsys.readouterr().err


def test_backup_roundtrip_through_the_cli(folder, env, capsys):
    vault, restored = env / "vault", env / "restored"
    assert run("backup", "create", folder, vault, "--name", "b1") == 0
    out = capsys.readouterr()
    digest = next(line for line in out.out.splitlines() if line.startswith("Manifest digest:")).split()[-1]
    assert "SAME drive" in out.err
    assert run("backup", "validate", vault / "b1", "--digest", digest) == 0
    assert run("backup", "validate", vault / "b1", "--digest", "0" * 64) == 1
    assert run("backup", "restore", vault / "b1", "--to", restored) == 0
    assert (restored / "doc05.txt").read_bytes() == (folder / "doc05.txt").read_bytes()

    (restored / "doc05.txt").write_text("my newer version")
    capsys.readouterr()
    assert run("backup", "restore", vault / "b1", "--to", restored) == 2         # never overwrites silently
    assert (restored / "doc05.txt").read_text() == "my newer version"
    assert run("backup", "restore", vault / "b1", "--to", restored, "--overwrite") == 2   # needs a terminal or --yes
    assert (restored / "doc05.txt").read_text() == "my newer version"
    assert run("backup", "restore", vault / "b1", "--to", restored, "--overwrite", "--yes") == 0
    assert (restored / "doc05.txt").read_bytes() == (folder / "doc05.txt").read_bytes()

    (vault / "b1" / "files" / "doc00.txt").write_text("corrupted")
    assert run("backup", "validate", vault / "b1") == 1
    assert "NOT intact" in capsys.readouterr().out
    assert run("backup", "restore", vault / "b1", "--to", env / "again") == 2
    assert run("backup", "restore", vault / "b1", "--to", env / "again2", "--digest", "0" * 64) == 2


def test_crypto_flow_through_the_cli(env, capsys):
    key = env / "keys" / "key.json"
    (env / "docs").mkdir()
    doc = env / "docs" / "report.txt"
    doc.write_text("quarterly numbers " * 50)
    assert run("crypto", "keygen", "--key", key) == 0
    assert run("crypto", "keygen", "--key", key) == 2                         # never overwrites a key
    assert run("crypto", "protect", doc, "--key", key) == 0
    protected = env / "docs" / "report.txt.bst"
    assert protected.exists() and doc.exists()                                # original kept
    assert b"quarterly" not in protected.read_bytes()
    assert run("crypto", "protect", env / "docs", "--key", key) == 2          # folders are refused
    out_dir = env / "opened"
    assert run("crypto", "open", protected, "--key", key, "--out-dir", out_dir) == 0
    assert (out_dir / "report.txt").read_text() == doc.read_text()
    assert run("crypto", "change-passphrase", "--key", key) == 0
    os.environ["BASTION_PASSPHRASE"] = PW + " new"
    assert run("crypto", "open", protected, "--key", key, "--out-dir", env / "opened2") == 0
    new_key = env / "keys" / "key2.json"
    os.environ["BASTION_PASSPHRASE_NEW"] = PW + " third"
    assert run("crypto", "rotate", protected, "--old-key", key, "--new-key", new_key) == 0
    capsys.readouterr()
    assert run("crypto", "open", protected, "--key", key, "--out-dir", env / "opened3") == 2   # old key no longer works
    os.environ["BASTION_PASSPHRASE"] = PW + " third"
    assert run("crypto", "open", protected, "--key", new_key, "--out-dir", env / "opened4") == 0


def test_passphrase_requires_terminal_or_env(env, monkeypatch, capsys):
    monkeypatch.delenv("BASTION_PASSPHRASE")
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert run("crypto", "keygen", "--key", env / "k.json") == 2
    assert "No terminal" in capsys.readouterr().err


def test_simulate_command_and_keep(env, capsys):
    base = env / "sim"
    assert run("simulate", "--base", base) == 0
    out = capsys.readouterr().out
    assert "FICTIONAL" in out and "Log chain: intact" in out and "header_lost" in out
    assert list(base.iterdir()) == []
    assert run("simulate", "--base", base, "--keep") == 0
    assert len(list(base.glob("run-*"))) == 1


def test_monitor_command_sees_changes_and_stops_on_ctrl_c(folder, env, monkeypatch, capsys):
    state = env / "state"
    calls = {"n": 0}

    def fake_sleep(_seconds):
        calls["n"] += 1
        if calls["n"] == 1:
            (folder / "created-while-monitoring.txt").write_text("hello " * 100)
            real_sleep(1.5)
        else:
            raise KeyboardInterrupt

    real_sleep = cli.time.sleep
    monkeypatch.setattr(cli.time, "sleep", fake_sleep)
    assert run("monitor", folder, "--state", state, "--verbose", "--polling") == 0
    out = capsys.readouterr().out
    assert "Monitoring" in out and "created-while-monitoring.txt" in out and "Stopping" in out
    assert run("log", "verify", "--state", state) == 0


def test_rules_command_prints_valid_json(capsys):
    assert run("rules") == 0
    assert json.loads(capsys.readouterr().out)["cooldown_seconds"] == 30


def _parser_raising(exc):
    import argparse

    def boom(_args):
        raise exc

    parser = argparse.ArgumentParser()
    parser.set_defaults(func=boom)
    return parser


def test_keyboard_interrupt_and_os_errors_have_clean_exit_codes(monkeypatch, capsys):
    monkeypatch.setattr(cli, "build_parser", lambda: _parser_raising(KeyboardInterrupt()))
    assert main([]) == 130
    monkeypatch.setattr(cli, "build_parser",
                        lambda: _parser_raising(PermissionError(13, "Permission denied", "/x")))
    assert main([]) == 2
    assert "Filesystem error" in capsys.readouterr().err
