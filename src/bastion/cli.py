"""Bastion command-line interface."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, NoReturn, Optional

from . import __version__
from .backup import create_backup, find_restore_collisions, restore_backup, verify_backup
from .canary import canary_events, deploy_canaries, load_canaries, load_canary_hashes
from .config import (
    RulesConfig,
    StatePaths,
    default_key_path,
    default_signing_key_paths,
    default_state_dir,
    load_config,
)
from .crypto import (
    change_passphrase,
    decrypt_file,
    encrypt_file,
    generate_keyfile,
    load_key,
    plan_open,
    plan_protect,
    rotate_files,
)
from .errors import BastionError
from .eventlog import EventLog, query_records, verify_log
from .events import DISCLAIMER, Alert, Event
from .fsutil import confirm_overwrite
from .inventory import (
    compare_inventories,
    diff_to_events,
    load_inventory,
    save_inventory,
    scan_directory,
)
from .monitor import Monitor
from .paths import ensure_disjoint, is_within, resolve_existing_dir, resolve_path
from .report import (
    analyze_state,
    assess_health,
    overall_ok,
    render_html,
    render_markdown,
    write_report,
)
from .rules import RuleEngine
from .signing import (
    append_checkpoint,
    create_checkpoint,
    generate_signing_keypair,
    load_checkpoints,
    load_private_key,
    load_public_key,
    verify_checkpoint,
)
from .simulation import run_simulation

# ---------------------------------------------------------------- presentation

_USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
_COLORS = {"high": "31;1", "medium": "33;1", "low": "36", "ok": "32", "dim": "2", "bold": "1"}


def paint(text: str, style: str) -> str:
    return f"\033[{_COLORS[style]}m{text}\033[0m" if _USE_COLOR and style in _COLORS else text


def out(msg: str = "") -> None:
    print(msg, flush=True)


def warn(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def local_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _short(sha: Optional[str]) -> str:
    return (sha[:12] + "…") if sha else "-"


def format_event(rec_data: Dict[str, Any]) -> str:
    path = rec_data["path"] + (f" -> {rec_data['dest_path']}" if rec_data.get("dest_path") else "")
    extras = [f"sha256={_short(rec_data.get('sha256'))}"]
    if rec_data.get("entropy") is not None:
        ent = f"entropy={rec_data['entropy']:.2f}"
        if rec_data.get("prev_entropy") is not None:
            ent += f" (was {rec_data['prev_entropy']:.2f})"
        extras.append(ent)
    if rec_data.get("note"):
        extras.append(f"note: {rec_data['note']}")
    return f"{local_time(rec_data['ts'])}  {rec_data['type']:<9} {path}  [{', '.join(extras)}]"


def format_alert(alert: Dict[str, Any], max_events: int = 5) -> str:
    sev = alert["severity"]
    lines = [
        paint(f"[{sev.upper()}] {alert['title']}", sev) + paint(f"  (rule: {alert['rule']})", "dim"),
        f"  What was observed: {alert['explanation']}",
        f"  Could be legitimate if it is: {alert['benign_causes']}",
        f"  What to do: {alert['suggestion']}",
    ]
    evs = alert.get("events", [])
    if evs:
        total = alert.get("total_related", len(evs))
        lines.append(f"  Related events (showing {min(max_events, len(evs))} of {total}):")
        lines += [f"    {format_event(e)}" for e in evs[:max_events]]
    lines.append(paint(f"  ⚠ {DISCLAIMER}", "dim"))
    return "\n".join(lines)


# ---------------------------------------------------------------- helpers

def resolve_state(args: argparse.Namespace, root: Optional[Path]) -> StatePaths:
    if getattr(args, "state", None):
        base = resolve_path(args.state)
    elif root is not None:
        base = default_state_dir(root)
    else:
        raise BastionError("Provide --state FOLDER or --folder MONITORED_FOLDER.")
    if root is not None:
        ensure_disjoint(base, root, label_a="The state directory", label_b="the monitored folder")
    return StatePaths(base)


def get_passphrase(prompt: str, env_var: str = "BASTION_PASSPHRASE", confirm: bool = False) -> str:
    env = os.environ.get(env_var)
    if env:
        warn(f"Warning: using the passphrase from the {env_var} variable (suitable only for demos/automation).")
        return env
    if not sys.stdin.isatty():
        raise BastionError(f"No terminal available to ask for the passphrase. Set {env_var} (demos only).")
    pw = getpass.getpass(prompt)
    if confirm and getpass.getpass("Repeat the passphrase: ") != pw:
        raise BastionError("The passphrases do not match.")
    return pw


_REL = re.compile(r"^(\d+)([smhd])$")


def parse_time_arg(text: str) -> float:
    m = _REL.match(text.strip())
    if m:
        return time.time() - int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        raise BastionError(f"Invalid date/time: '{text}'. Use '30m', '2h', '1d' or '2026-10-24T14:30'.") from None


# ---------------------------------------------------------------- commands

def cmd_inventory(args: argparse.Namespace) -> int:
    root = resolve_existing_dir(args.folder, label="folder to inventory")
    state = resolve_state(args, root)
    config = load_config(args.rules)
    state.ensure()
    if state.inventory.exists():
        if not args.update:
            raise BastionError(
                f"A baseline inventory already exists at {state.inventory}.\n"
                "To compare, use 'bastion verify'. To replace the baseline, use --update "
                "(the previous one is preserved). Note: updating the baseline after an incident erases the comparison point."
            )
        backup_name = state.base / f"inventory-previous-{time.strftime('%Y%m%d-%H%M%S')}.json"
        os.replace(state.inventory, backup_name)
        out(f"Previous inventory preserved at {backup_name}")
    out(f"Scanning {root} ...")
    inv = scan_directory(root, config.ignore_patterns, progress=lambda n: out(f"  {n} files..."))
    save_inventory(inv, state.inventory)
    log = EventLog(state.log)
    log.append("system", {"action": "inventory_created", "root": str(root),
                           "files": len(inv.entries), "root_hash": inv.root_hash()})
    out(paint(f"Inventory created: {len(inv.entries)} files.", "ok"))
    for item in inv.skipped:
        warn(f"  skipped: {item['path']} ({item['reason']})")
    out(f"Root hash: {inv.root_hash()}")
    out("Tip: write the root hash down somewhere else (paper, password manager, another computer).")
    out(f"State stored in: {state.base}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    root = resolve_existing_dir(args.folder, label="monitored folder")
    state = resolve_state(args, root)
    if not state.inventory.exists():
        raise BastionError(f"There is no baseline inventory yet. Create one with: bastion inventory {args.folder}")
    old = load_inventory(state.inventory)
    config = load_config(args.rules)
    out("Comparing the current folder with the baseline inventory...")
    new = scan_directory(root, config.ignore_patterns, progress=lambda n: out(f"  {n} files..."))
    diff = compare_inventories(old, new)

    def section(title: str, items: list) -> None:
        if items:
            out(f"\n{title} ({len(items)}):")
            for it in items[:20]:
                out(f"  - {it[0] + ' -> ' + it[1] if isinstance(it, tuple) else it}")
            if len(items) > 20:
                out(f"  ... and {len(items) - 20} more")

    if diff.is_clean:
        out(paint("No differences: the folder matches the baseline inventory.", "ok"))
    else:
        out(f"Changes since the baseline: {diff.total_changes} (unchanged: {diff.unchanged})")
        section("Modified", diff.modified)
        section("Renamed (same content)", diff.renamed)
        section("Renamed with different content", diff.renamed_changed)
        section("New", diff.added)
        section("Removed", diff.removed)
    for item in new.skipped:
        warn(f"  skipped: {item['path']} ({item['reason']})")

    state.ensure()
    log = EventLog(state.log)
    engine = RuleEngine(config, load_canaries(state.canaries))
    alerts: List[Alert] = []
    now = time.time()
    events = diff_to_events(old, new, diff, now)
    events += canary_events(load_canary_hashes(state.canaries),
                            {p: e.sha256 for p, e in new.entries.items()},
                            {e.path for e in events if e.type != "created"}, now)
    for ev in events:
        log.append("event", ev.to_dict())
        for alert in engine.process(ev):
            log.append("alert", alert.to_dict())
            alerts.append(alert)
    log.append("system", {"action": "verification", "changes": diff.total_changes,
                          "alerts": len(alerts), "root_hash_base": old.root_hash(),
                          "root_hash_now": new.root_hash()})
    if alerts:
        out(paint(f"\n{len(alerts)} signal(s) for analysis:", "bold"))
        for a in alerts:
            out("\n" + format_alert(a.to_dict()))
    elif not diff.is_clean:
        out("\nNo rule was triggered (the changes stayed below the configured thresholds).")
    return 1 if alerts else 0


def cmd_monitor(args: argparse.Namespace) -> int:
    root = resolve_existing_dir(args.folder, label="monitored folder")
    state = resolve_state(args, root)
    config = load_config(args.rules)

    def on_event(ev: Event) -> None:
        if args.verbose:
            out(format_event(ev.to_dict()))

    def on_alert(alert: Alert) -> None:
        out("\n" + format_alert(alert.to_dict()) + "\n")

    monitor = Monitor(root, state, config, polling=args.polling, on_event=on_event,
                      on_alert=on_alert, on_error=warn,
                      on_progress=lambda n: out(f"  {n} files..."))
    out(f"Preparing the monitor for {root} ...")
    monitor.start()
    if monitor.baseline_created:
        out("Baseline inventory created automatically (there was none).")
    out(paint("Monitoring. Press Ctrl+C to stop.", "ok"))
    out("Tip: if the folder changed while the monitor was off, run 'bastion verify' first.")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        out("\nStopping...")
    finally:
        monitor.stop()
    out(f"Alerts in this session: {len(monitor.alerts)}. Review them with: bastion events --state {state.base}")
    return 0


def cmd_events(args: argparse.Namespace) -> int:
    root = resolve_existing_dir(args.folder, label="monitored folder") if args.folder else None
    state = resolve_state(args, root)
    if not state.log.exists():
        out("No events recorded yet.")
        return 0
    check = verify_log(state.log)
    if not check.ok:
        warn(paint(f"WARNING: the log chain does not verify ({check.error}). Treat the history as suspect.", "high"))
    kind = "alert" if args.alerts else ("event" if args.events_only else None)
    records = query_records(
        state.log, kind=kind, event_type=args.type, rule=args.rule,
        since=parse_time_arg(args.since) if args.since else None,
        until=parse_time_arg(args.until) if args.until else None,
        path_contains=args.path, limit=args.limit)
    if args.json:
        out(json.dumps(records, ensure_ascii=False, indent=2))
        return 0
    if not records:
        out("No records match those filters.")
        return 0
    for rec in records:
        data = rec["data"]
        if rec["kind"] == "event":
            out(format_event(data))
        elif rec["kind"] == "alert":
            out(f"{local_time(rec['ts'])}  " + paint(f"ALERT[{data['severity']}]", data["severity"])
                + f" {data['title']} (rule: {data['rule']}, observed {data['observed']}/{data['threshold']})")
        else:
            details = json.dumps({k: v for k, v in data.items() if k != "action"}, ensure_ascii=False)
            out(f"{local_time(rec['ts'])}  system    {data.get('action')}  {details}")
    out(f"\n{len(records)} record(s). Use --json to export.")
    return 0


def cmd_log_verify(args: argparse.Namespace) -> int:
    root = resolve_existing_dir(args.folder, label="monitored folder") if args.folder else None
    state = resolve_state(args, root)
    result = verify_log(state.log, anchor=args.anchor)
    if not result.ok:
        out(paint(f"CHAIN BROKEN: {result.error}", "high"))
        out(f"Records intact up to #{result.records}.")
        return 1
    out(paint(f"Chain intact: {result.records} record(s).", "ok"))
    out(f"Head hash: {result.head}")
    status = 0
    if args.anchor:
        if result.anchor_found:
            out(paint("The given anchor is present in the chain (nothing before it was removed).", "ok"))
        else:
            out(paint("The given anchor is NOT in the chain: the log may have been truncated or replaced.", "high"))
            status = 1
    if args.public_key:
        checkpoint_file = Path(args.checkpoint).expanduser() if args.checkpoint else state.checkpoints
        public = load_public_key(resolve_path(args.public_key))
        docs = load_checkpoints(checkpoint_file)
        out(f"Checking {len(docs)} signed checkpoint(s) from {checkpoint_file} (key {public.key_id[:8]}…):")
        for doc in docs:
            res = verify_checkpoint(state.log, doc, public)
            if res.ok:
                out(paint(f"  OK      {res.created_at}  covers {res.records} records "
                          f"({res.records_since} added since)", "ok"))
            else:
                out(paint(f"  FAILED  {res.created_at}  covers {res.records} records: {res.error}", "high"))
                status = 1
    elif args.checkpoint:
        raise BastionError("--checkpoint also needs --public-key (verification uses the PUBLIC key only).")
    elif not args.anchor:
        out("Tip: sign the head with 'bastion log checkpoint' (or write it down off the machine and use --anchor).")
    return status


def cmd_log_checkpoint(args: argparse.Namespace) -> int:
    root = resolve_existing_dir(args.folder, label="monitored folder") if args.folder else None
    state = resolve_state(args, root)
    key_path = resolve_path(args.signing_key)
    if root is not None and is_within(key_path, root):
        raise BastionError("The signing key must not live inside the monitored folder.")
    private, key_id = load_private_key(key_path, get_passphrase("Signing key passphrase: "))
    doc = create_checkpoint(state.log, private, key_id, note=args.note or "")
    append_checkpoint(state.checkpoints, doc)
    EventLog(state.log).append("system", {"action": "checkpoint_created", "records": doc["records"],
                                          "head": doc["head"], "key_id": key_id})
    text = json.dumps(doc, indent=2, sort_keys=True)
    if args.output:
        target = write_report(resolve_path(args.output), text + "\n")
        out(paint(f"Checkpoint saved to {target}", "ok"))
    else:
        out(text)
    out(paint(f"Signed: {doc['records']} records, head {doc['head'][:16]}…", "ok"))
    out("Copy this checkpoint somewhere that is NOT this machine (email it to yourself, print it, attach it to a ticket).")
    out("Verify any time, on any computer, with the public key: bastion log verify --state ... --public-key PUB --checkpoint FILE")
    return 0


def cmd_sign_keygen(args: argparse.Namespace) -> int:
    default_private, default_public = default_signing_key_paths()
    private = resolve_path(args.private or default_private)
    public = resolve_path(args.public or default_public)
    pw = get_passphrase("Choose a passphrase for the signing key (min. 12 characters): ", confirm=True)
    key_id = generate_signing_keypair(private, public, pw)
    out(paint(f"Signing key created: {private}", "ok"))
    out(f"Public key: {public}   (key id {key_id[:8]}…)")
    out("The PRIVATE key is sealed with your passphrase. Ideally move it to another computer or a USB drive,")
    out("and keep only the public key (not secret) wherever you verify checkpoints.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    root = resolve_existing_dir(args.folder, label="monitored folder") if args.folder else None
    state = resolve_state(args, root)
    if not state.base.exists():
        raise BastionError(f"No Bastion state found at {state.base}. Start with: bastion inventory FOLDER")
    public = load_public_key(resolve_path(args.public_key)) if args.public_key else None
    analysis = analyze_state(state, public_key=public)
    findings = assess_health(analysis)
    if args.json:
        out(json.dumps({"ok": overall_ok(findings),
                        "findings": [{"level": f.level, "text": f.text} for f in findings],
                        "analysis": analysis.to_dict()}, ensure_ascii=False, indent=2))
        return 0 if overall_ok(findings) else 1
    out(paint(f"== Bastion status ==  ({state.base})", "bold"))
    marks = {"ok": ("ok", "[ OK ]"), "warn": ("medium", "[WARN]"), "bad": ("high", "[ !! ]")}
    for f in findings:
        style, mark = marks[f.level]
        out(f"{paint(mark, style)} {f.text}")
    out("")
    out(paint("Needs attention." if not overall_ok(findings) else "No blocking problems found.",
              "high" if not overall_ok(findings) else "ok"))
    return 0 if overall_ok(findings) else 1


def cmd_report(args: argparse.Namespace) -> int:
    root = resolve_existing_dir(args.folder, label="monitored folder") if args.folder else None
    state = resolve_state(args, root)
    if not state.log.exists():
        raise BastionError(f"There is no event log at {state.log} yet: nothing to report.")
    public = load_public_key(resolve_path(args.public_key)) if args.public_key else None
    analysis = analyze_state(state, public_key=public)
    renderers = {
        "html": lambda: render_html(analysis, assess_health(analysis)),
        "md": lambda: render_markdown(analysis),
        "json": lambda: json.dumps(analysis.to_dict(), ensure_ascii=False, indent=2),
    }
    content = renderers[args.format]() + "\n"
    if args.output == "-":
        out(content.rstrip("\n"))
        return 0
    if args.output:
        target = resolve_path(args.output)
    else:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        target = state.reports / f"bastion-report-{stamp}.{args.format}"
    if root is not None and is_within(target, root):
        raise BastionError("Reports contain file names and must not be written inside the monitored folder.")
    target.parent.mkdir(parents=True, exist_ok=True)
    write_report(target, content)
    out(paint(f"Report written to {target}", "ok"))
    out("It contains file names from the monitored folder: treat it as sensitive "
        "(you can protect it with 'bastion crypto protect').")
    return 0


def cmd_canary_create(args: argparse.Namespace) -> int:
    root = resolve_existing_dir(args.folder, label="monitored folder")
    state = resolve_state(args, root)
    state.ensure()
    names = deploy_canaries(root, state.canaries)
    out(paint("Canaries created:", "ok"))
    for n in names:
        out(f"  - {root / n}")
    out("Nobody should open or edit these files. Restart the monitor so it loads the canaries.")
    out("Tip: create canaries BEFORE the baseline inventory (or refresh the baseline with 'bastion inventory --update').")
    out("'bastion verify' also checks whether the canaries changed or vanished since creation.")
    return 0


def cmd_simulate(args: argparse.Namespace) -> int:
    base = resolve_path(args.base)
    out(paint("== Bastion safe simulation ==", "bold"))
    out("Everything happens on FICTIONAL files inside a temporary folder; no real data is touched.\n")
    report = run_simulation(
        base, keep=args.keep, pause=args.pause, say=out,
        on_alert=lambda a: out("\n" + format_alert(a.to_dict(), max_events=3) + "\n"))
    out(paint("\n== Summary ==", "bold"))
    out(f"Alerts raised: {len(report.alerts)}; rules triggered: {', '.join(sorted(report.rules_triggered)) or 'none'}")
    if report.log_check:
        status = "intact" if report.log_check.ok else "BROKEN"
        out(f"Log chain: {status} ({report.log_check.records} records).")
    if report.kept:
        out(f"Simulation files kept at {report.run_dir} (inspect events.jsonl inside 'state/').")
    else:
        out("Temporary simulation folder removed.")
    return 0 if report.alerts else 1


def cmd_backup_create(args: argparse.Namespace) -> int:
    config = load_config(args.rules)
    result = create_backup(Path(args.source), Path(args.destination), name=args.name, ignore=config.ignore_patterns)
    out(paint(f"Backup created: {result.path}", "ok"))
    out(f"{result.files} file(s), {result.total_bytes} bytes. Root hash: {result.root_hash}")
    out(f"Manifest digest: {result.manifest_digest}")
    out("Write the digest down off the machine; use 'bastion backup validate --digest' to check it later.")
    for s in result.skipped:
        warn(f"  skipped: {s['path']} ({s['reason']})")
    for w in result.warnings:
        warn(paint(f"Warning: {w}", "medium"))
    out("Good practice: keep at least one offline/immutable copy in another location, out of reach of the monitored machine.")
    return 0


def cmd_backup_validate(args: argparse.Namespace) -> int:
    report = verify_backup(Path(args.backup), expected_digest=args.digest)
    out(f"Files checked: {report.checked}")
    problems = [
        ("Inconsistent manifest (root hash mismatch)", [] if report.manifest_ok else ["manifest.json"]),
        ("Missing", report.missing), ("Corrupted/altered", report.corrupted),
        ("Unexpected (not listed in the manifest)", report.unexpected),
        ("Unsafe paths in the manifest", report.invalid_paths),
    ]
    for title, items in problems:
        if items:
            out(paint(f"{title} ({len(items)}):", "high"))
            for it in items[:20]:
                out(f"  - {it}")
    if report.digest_matches is True:
        out(paint("Manifest digest matches the value you provided.", "ok"))
    elif report.digest_matches is False:
        out(paint("Manifest digest DIFFERS from the one you provided: the manifest was altered.", "high"))
    out(f"Manifest digest: {report.digest}")
    out(paint("Backup intact.", "ok") if report.ok else paint("Backup is NOT intact: do not trust it.", "high"))
    return 0 if report.ok else 1


def cmd_backup_restore(args: argparse.Namespace) -> int:
    backup, target = Path(args.backup), resolve_path(args.to)
    if args.digest and not verify_backup(backup, expected_digest=args.digest).digest_matches:
        raise BastionError("The manifest digest does not match the one you provided; restore cancelled.")
    collisions = find_restore_collisions(backup, target)
    confirm_overwrite(collisions, allow_overwrite=args.overwrite, assume_yes=args.yes)
    result = restore_backup(backup, target, overwrite=bool(collisions))
    out(paint(f"Restore completed at {result.target}", "ok"))
    out(f"Files restored: {result.restored}; already identical (kept): {result.skipped_identical}. Hashes verified after copy.")
    return 0


def cmd_crypto_keygen(args: argparse.Namespace) -> int:
    path = resolve_path(args.key)
    pw = get_passphrase("Choose a passphrase (min. 12 characters): ", confirm=True)
    key_id = generate_keyfile(path, pw)
    out(paint(f"Key file created: {path}", "ok"))
    out(f"Key ID: {key_id[:8]}…  (permissions 0600; the data key is encrypted with your passphrase)")
    out("Keep this file and the passphrase SEPARATE from the protected files, and back up the key.")
    out("Without the key and the passphrase there is no way to recover the files.")
    return 0


def cmd_crypto_protect(args: argparse.Namespace) -> int:
    keyfile = resolve_path(args.key)
    plan = plan_protect(args.files, Path(args.out_dir) if args.out_dir else None, keyfile)
    key = load_key(keyfile, get_passphrase("Key passphrase: "))
    collisions = [dst for _, dst in plan if dst.exists()]
    confirm_overwrite(collisions, allow_overwrite=args.overwrite, assume_yes=args.yes)
    for src, dst in plan:
        encrypt_file(key, src, dst, overwrite=bool(collisions))
        out(f"Protected: {src.name} -> {dst}")
    out("The originals were KEPT. Test with 'bastion crypto open' before deleting them.")
    return 0


def cmd_crypto_open(args: argparse.Namespace) -> int:
    key = load_key(resolve_path(args.key), get_passphrase("Key passphrase: "))
    plan = plan_open(args.files, Path(args.out_dir) if args.out_dir else None)
    collisions = [dst for _, dst in plan if dst.exists()]
    confirm_overwrite(collisions, allow_overwrite=args.overwrite, assume_yes=args.yes)
    for src, dst in plan:
        decrypt_file(key, src, dst, overwrite=bool(collisions))
        out(f"Opened: {src.name} -> {dst}")
    return 0


def cmd_crypto_change_passphrase(args: argparse.Namespace) -> int:
    path = resolve_path(args.key)
    old = get_passphrase("Current passphrase: ")
    new = get_passphrase("New passphrase (min. 12 characters): ", env_var="BASTION_PASSPHRASE_NEW", confirm=True)
    change_passphrase(path, old, new)
    out(paint("Passphrase changed. The data key is the same: existing files keep opening.", "ok"))
    return 0


def cmd_crypto_rotate(args: argparse.Namespace) -> int:
    old_path, new_path = resolve_path(args.old_key), resolve_path(args.new_key)
    files = [p for p, _ in plan_open(args.files, None)]
    old_key = load_key(old_path, get_passphrase("OLD key passphrase: "))
    new_pw = get_passphrase("NEW key passphrase (min. 12 characters): ", env_var="BASTION_PASSPHRASE_NEW", confirm=True)
    new_id = generate_keyfile(new_path, new_pw)
    new_key = load_key(new_path, new_pw)
    done = rotate_files(old_key, new_key, files)
    out(paint(f"{len(done)} file(s) re-encrypted with the new key (id {new_id[:8]}…).", "ok"))
    out("After confirming everything opens, retire the old key (and its copies) safely.")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    out(json.dumps(RulesConfig.default().to_dict(), ensure_ascii=False, indent=2))
    return 0


# ---------------------------------------------------------------- parser

class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        warn(f"Usage error: {message}\nRun '{self.prog} --help' to see the options.")
        raise SystemExit(2)


def _common(p: argparse.ArgumentParser, rules: bool = True) -> None:
    p.add_argument("--state", metavar="FOLDER", help="where to keep inventory and log (default: ~/.bastion/state/<folder>); must be OUTSIDE the monitored folder")
    if rules:
        p.add_argument("--rules", metavar="FILE.json", help="custom rules (see examples/rules.example.json)")


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="bastion",
        description="Bastion: defensive ransomware-signal detection and file integrity protection (educational project).",
        epilog="Alerts are SIGNALS FOR ANALYSIS, not verdicts. Start with: bastion simulate",
    )
    p.add_argument("--version", action="version", version=f"bastion {__version__}")
    sub = p.add_subparsers(dest="command", metavar="COMMAND", required=True, parser_class=_Parser)

    s = sub.add_parser("inventory", help="create the baseline inventory (SHA-256 + entropy) of a folder")
    s.add_argument("folder"); _common(s)
    s.add_argument("--update", action="store_true", help="replace the existing baseline (the previous one is preserved)")
    s.set_defaults(func=cmd_inventory)

    s = sub.add_parser("verify", help="compare the folder with the baseline inventory and apply the rules")
    s.add_argument("folder"); _common(s)
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("monitor", help="monitor the folder in real time and show alerts")
    s.add_argument("folder"); _common(s)
    s.add_argument("--verbose", action="store_true", help="show every event, not just alerts")
    s.add_argument("--polling", action="store_true", help="use periodic scanning (for network folders)")
    s.set_defaults(func=cmd_monitor)

    s = sub.add_parser("events", help="query recorded events and alerts")
    s.add_argument("--folder", help="monitored folder (to locate the default state)"); _common(s, rules=False)
    g = s.add_mutually_exclusive_group()
    g.add_argument("--alerts", action="store_true", help="alerts only")
    g.add_argument("--events-only", action="store_true", help="file events only")
    s.add_argument("--type", choices=["created", "modified", "moved", "deleted"])
    s.add_argument("--rule", help="filter alerts by rule name")
    s.add_argument("--since", help="e.g. 30m, 2h, 1d or 2026-10-24T14:30")
    s.add_argument("--until")
    s.add_argument("--path", help="part of the file path")
    s.add_argument("--limit", type=int, default=50, help="last N records (default 50)")
    s.add_argument("--json", action="store_true", help="JSON output")
    s.set_defaults(func=cmd_events)

    log = sub.add_parser("log", help="event log integrity").add_subparsers(dest="sub", required=True, parser_class=_Parser)
    s = log.add_parser("verify", help="check the hash chain of the log")
    s.add_argument("--folder"); _common(s, rules=False)
    s.add_argument("--anchor", metavar="HASH", help="head hash noted earlier; detects truncation")
    s.add_argument("--public-key", metavar="FILE", help="public key: also verify the signed checkpoints")
    s.add_argument("--checkpoint", metavar="FILE", help="checkpoint file to verify (default: the ones stored in the state folder)")
    s.set_defaults(func=cmd_log_verify)
    s = log.add_parser("checkpoint", help="sign the current log head (Ed25519) so history cannot be silently rewritten")
    s.add_argument("--folder"); _common(s, rules=False)
    s.add_argument("--signing-key", default=str(default_signing_key_paths()[0]), metavar="FILE",
                   help=f"private signing key (default: {default_signing_key_paths()[0]})")
    s.add_argument("--output", metavar="FILE", help="also save the checkpoint to this new file")
    s.add_argument("--note", help="short free text stored inside the signed checkpoint")
    s.set_defaults(func=cmd_log_checkpoint)

    sg = sub.add_parser("sign", help="signing keys for log checkpoints").add_subparsers(dest="sub", required=True, parser_class=_Parser)
    s = sg.add_parser("keygen", help="create an Ed25519 signing key pair (private key sealed with a passphrase)")
    s.add_argument("--private", metavar="FILE", help=f"default: {default_signing_key_paths()[0]}")
    s.add_argument("--public", metavar="FILE", help=f"default: {default_signing_key_paths()[1]}")
    s.set_defaults(func=cmd_sign_keygen)

    s = sub.add_parser("status", help="one-screen health check of the protection (exit 1 if something needs attention)")
    s.add_argument("--folder", help="monitored folder (to locate the default state)"); _common(s, rules=False)
    s.add_argument("--public-key", metavar="FILE", help="verify signed checkpoints with this public key")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("report", help="incident report from the evidence (HTML, Markdown or JSON)")
    s.add_argument("--folder", help="monitored folder (to locate the default state)"); _common(s, rules=False)
    s.add_argument("--format", choices=["html", "md", "json"], default="html")
    s.add_argument("--output", metavar="FILE", help="file to create (default: <state>/reports/...); '-' prints to the screen")
    s.add_argument("--public-key", metavar="FILE", help="verify signed checkpoints with this public key")
    s.set_defaults(func=cmd_report)

    canary = sub.add_parser("canary", help="canary files (honeyfiles)").add_subparsers(dest="sub", required=True, parser_class=_Parser)
    s = canary.add_parser("create", help="create canary files in the monitored folder")
    s.add_argument("folder"); _common(s, rules=False)
    s.set_defaults(func=cmd_canary_create)

    s = sub.add_parser("simulate", help="safe simulation with fictional files")
    s.add_argument("--base", default=".bastion_sim", help="temporary simulation folder (default: ./.bastion_sim)")
    s.add_argument("--keep", action="store_true", help="do not delete the simulation folder at the end")
    s.add_argument("--pause", type=float, default=0.0, help="seconds to pause between phases (for presenting)")
    s.set_defaults(func=cmd_simulate)

    bk = sub.add_parser("backup", help="demo backup").add_subparsers(dest="sub", required=True, parser_class=_Parser)
    s = bk.add_parser("create", help="create a backup with manifest and hashes")
    s.add_argument("source"); s.add_argument("destination"); s.add_argument("--name")
    s.add_argument("--rules", metavar="FILE.json")
    s.set_defaults(func=cmd_backup_create)
    s = bk.add_parser("validate", help="check a backup's integrity")
    s.add_argument("backup"); s.add_argument("--digest", help="manifest digest noted at creation time")
    s.set_defaults(func=cmd_backup_validate)
    s = bk.add_parser("restore", help="restore a valid backup into a test folder")
    s.add_argument("backup"); s.add_argument("--to", required=True, metavar="FOLDER", help="destination folder (use a test folder)")
    s.add_argument("--digest"); s.add_argument("--overwrite", action="store_true", help="allow replacing different files (requires confirmation)")
    s.add_argument("--yes", action="store_true", help="confirm the overwrite without asking")
    s.set_defaults(func=cmd_backup_restore)

    cr = sub.add_parser("crypto", help="encryption of selected files (AES-256-GCM)").add_subparsers(dest="sub", required=True, parser_class=_Parser)
    key_help = f"key file (default: {default_key_path()})"
    s = cr.add_parser("keygen", help="create a passphrase-protected key file")
    s.add_argument("--key", default=str(default_key_path()), help=key_help)
    s.set_defaults(func=cmd_crypto_keygen)
    for name, fn, help_ in (("protect", cmd_crypto_protect, "encrypt chosen files (creates .bst; keeps the original)"),
                            ("open", cmd_crypto_open, "decrypt .bst files")):
        s = cr.add_parser(name, help=help_)
        s.add_argument("files", nargs="+", metavar="FILE")
        s.add_argument("--key", default=str(default_key_path()), help=key_help)
        s.add_argument("--out-dir", metavar="FOLDER")
        s.add_argument("--overwrite", action="store_true"); s.add_argument("--yes", action="store_true")
        s.set_defaults(func=fn)
    s = cr.add_parser("change-passphrase", help="change the key file passphrase (same data key)")
    s.add_argument("--key", default=str(default_key_path()), help=key_help)
    s.set_defaults(func=cmd_crypto_change_passphrase)
    s = cr.add_parser("rotate", help="generate a new key and re-encrypt .bst files")
    s.add_argument("files", nargs="+", metavar="FILE.bst")
    s.add_argument("--old-key", required=True); s.add_argument("--new-key", required=True)
    s.set_defaults(func=cmd_crypto_rotate)

    s = sub.add_parser("rules", help="print the default rules as JSON (a starting point to customize)")
    s.set_defaults(func=cmd_rules)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except BastionError as exc:
        warn(paint(f"Error: {exc}", "high"))
        return 2
    except KeyboardInterrupt:
        warn("\nInterrupted.")
        return 130
    except OSError as exc:
        warn(paint(f"Filesystem error: {exc.strerror or exc} ({exc.filename or ''})", "high"))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
