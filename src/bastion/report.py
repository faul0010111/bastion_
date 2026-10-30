"""Evidence analysis, health status and incident reports.

``analyze_state`` reads a state folder (log, inventory, canaries, checkpoints)
and produces an ``Analysis``: counts, alerts, a timeline, monitoring sessions
and *coverage gaps* (periods when no monitor was running), plus the integrity
status of the evidence itself.

``assess_health`` turns an analysis into a short list of findings for
``bastion status``. ``render_html`` / ``render_markdown`` produce a report meant
to be attached to a ticket or sent to whoever handles security.

The HTML report is a single self-contained file: no scripts, no external
resources, a restrictive Content-Security-Policy, and every value coming from
the log is escaped (file names are attacker-controlled data).
"""

from __future__ import annotations

import html
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from itertools import pairwise
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .canary import load_canaries
from .config import StatePaths
from .errors import BastionError, SigningError
from .eventlog import LogVerification, read_records, verify_log
from .events import DISCLAIMER, iso_utc
from .fsutil import atomic_write_bytes
from .inventory import load_inventory
from .signing import CheckpointResult, PublicKey, load_checkpoints, verify_checkpoint

SEVERITIES = ("high", "medium", "low")
MAX_ALERTS_IN_REPORT = 100
MAX_RELATED_IN_REPORT = 10
_BUCKET_CHOICES = (1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600, 7200, 21600, 86400)
DAY = 86400.0


# ----------------------------------------------------------------------- analysis

@dataclass
class Session:
    start: float
    stop: Optional[float] = None
    last_seen: float = 0.0
    alerts: int = 0

    @property
    def ended_cleanly(self) -> bool:
        return self.stop is not None


@dataclass
class Gap:
    start: float
    end: float
    after_unclean_stop: bool

    @property
    def seconds(self) -> float:
        return max(0.0, self.end - self.start)


@dataclass
class Timeline:
    start: float
    bucket_seconds: int
    events: List[int]
    alerts: List[int]


@dataclass
class CheckpointStatus:
    created_at: str
    records: int
    key_id: str
    ok: Optional[bool]            # None = not verified (no public key given)
    detail: str = ""


@dataclass
class Analysis:
    generated_at: float
    state_dir: str
    log_check: LogVerification
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    event_counts: Dict[str, int] = field(default_factory=dict)
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    rule_counts: Dict[str, int] = field(default_factory=dict)
    severity_counts: Dict[str, int] = field(default_factory=dict)
    top_dirs: List[Tuple[str, int]] = field(default_factory=list)
    timeline: Optional[Timeline] = None
    sessions: List[Session] = field(default_factory=list)
    gaps: List[Gap] = field(default_factory=list)
    inventory: Optional[Dict[str, Any]] = None
    inventory_error: Optional[str] = None
    canaries: int = 0
    checkpoints: List[CheckpointStatus] = field(default_factory=list)
    verifications: int = 0

    @property
    def total_events(self) -> int:
        return sum(self.event_counts.values())

    def alerts_since(self, ts: float) -> List[Dict[str, Any]]:
        return [a for a in self.alerts if a.get("ts", 0) >= ts]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": iso_utc(self.generated_at),
            "bastion_version": __version__,
            "state_dir": self.state_dir,
            "log": {"ok": self.log_check.ok, "records": self.log_check.records,
                    "head": self.log_check.head, "error": self.log_check.error},
            "first_record": iso_utc(self.first_ts) if self.first_ts else None,
            "last_record": iso_utc(self.last_ts) if self.last_ts else None,
            "event_counts": self.event_counts,
            "severity_counts": self.severity_counts,
            "rule_counts": self.rule_counts,
            "top_directories": [{"path": p, "events": n} for p, n in self.top_dirs],
            "alerts": self.alerts,
            "sessions": [{"start": iso_utc(s.start), "stop": iso_utc(s.stop) if s.stop else None,
                          "alerts": s.alerts} for s in self.sessions],
            "coverage_gaps": [{"start": iso_utc(g.start), "end": iso_utc(g.end),
                               "seconds": round(g.seconds, 1),
                               "after_unclean_stop": g.after_unclean_stop} for g in self.gaps],
            "inventory": self.inventory,
            "inventory_error": self.inventory_error,
            "canaries": self.canaries,
            "checkpoints": [vars(c) for c in self.checkpoints],
            "disclaimer": DISCLAIMER,
        }


def _parent_dir(path: str) -> str:
    parent = PurePosixPath(path).parent.as_posix()
    return "(root of the monitored folder)" if parent in (".", "") else parent


def choose_bucket(span_seconds: float) -> int:
    """Smallest 'nice' bucket size that keeps the timeline at 60 bars or fewer."""
    for size in _BUCKET_CHOICES:
        if span_seconds / size <= 60:
            return size
    return _BUCKET_CHOICES[-1]


def _build_timeline(stamps_events: List[float], stamps_alerts: List[float]) -> Optional[Timeline]:
    every = stamps_events + stamps_alerts
    if not every:
        return None
    first, last = min(every), max(every)
    size = choose_bucket(last - first)
    count = int((last - first) // size) + 1
    events, alerts = [0] * count, [0] * count
    for ts in stamps_events:
        events[int((ts - first) // size)] += 1
    for ts in stamps_alerts:
        alerts[int((ts - first) // size)] += 1
    return Timeline(first, size, events, alerts)


def _sessions_and_gaps(system_records: List[Dict[str, Any]],
                       alert_stamps: List[float]) -> Tuple[List[Session], List[Gap]]:
    sessions: List[Session] = []
    current: Optional[Session] = None
    for rec in system_records:
        action, ts = rec["data"].get("action"), rec["ts"]
        if action == "monitor_start":
            current = Session(start=ts, last_seen=ts)
            sessions.append(current)
        elif action == "monitor_stop" and current is not None:
            current.stop = current.last_seen = ts
            current = None
        elif current is not None:
            current.last_seen = ts
    for session in sessions:
        end = session.stop if session.stop is not None else float("inf")
        session.alerts = sum(1 for a in alert_stamps if session.start <= a <= end)
    gaps: List[Gap] = []
    for prev, nxt in pairwise(sessions):
        gaps.append(Gap(prev.stop if prev.stop is not None else prev.last_seen, nxt.start,
                        after_unclean_stop=prev.stop is None))
    return sessions, gaps


def analyze_state(
    state: StatePaths,
    *,
    public_key: Optional[PublicKey] = None,
    now: Optional[float] = None,
) -> Analysis:
    """Read a state folder. Never modifies it."""
    now = time.time() if now is None else now
    log_check = verify_log(state.log)
    result = Analysis(generated_at=now, state_dir=str(state.base), log_check=log_check)

    event_counts: Counter = Counter()
    dir_counts: Counter = Counter()
    event_stamps: List[float] = []
    alert_stamps: List[float] = []
    system_records: List[Dict[str, Any]] = []
    for rec in read_records(state.log):
        try:
            kind, ts, data = rec["kind"], float(rec["ts"]), rec["data"]
        except (KeyError, TypeError, ValueError):
            continue
        result.first_ts = ts if result.first_ts is None else min(result.first_ts, ts)
        result.last_ts = ts if result.last_ts is None else max(result.last_ts, ts)
        if kind == "event":
            event_counts[data.get("type", "?")] += 1
            dir_counts[_parent_dir(str(data.get("dest_path") or data.get("path", "")))] += 1
            event_stamps.append(ts)
        elif kind == "alert":
            result.alerts.append(data)
            alert_stamps.append(ts)
        elif kind == "system":
            system_records.append(rec)
            if data.get("action") == "verification":
                result.verifications += 1

    result.event_counts = dict(event_counts)
    result.rule_counts = dict(Counter(a.get("rule", "?") for a in result.alerts))
    result.severity_counts = {s: sum(1 for a in result.alerts if a.get("severity") == s)
                              for s in SEVERITIES}
    result.top_dirs = dir_counts.most_common(10)
    result.timeline = _build_timeline(event_stamps, alert_stamps)
    result.sessions, result.gaps = _sessions_and_gaps(system_records, alert_stamps)

    if state.inventory.exists():
        try:
            inv = load_inventory(state.inventory)
            result.inventory = {"root": inv.root, "files": len(inv.entries),
                                "root_hash": inv.root_hash(), "created_at": iso_utc(inv.created_at)}
        except BastionError as exc:
            result.inventory_error = str(exc)
    try:
        result.canaries = len(load_canaries(state.canaries))
    except (BastionError, OSError, ValueError):
        result.canaries = 0
    result.checkpoints = _checkpoint_statuses(state, public_key)
    return result


def _checkpoint_statuses(state: StatePaths, public_key: Optional[PublicKey]) -> List[CheckpointStatus]:
    if not state.checkpoints.exists():
        return []
    try:
        docs = load_checkpoints(state.checkpoints)
    except SigningError as exc:
        return [CheckpointStatus("?", 0, "?", False, f"checkpoint file unreadable: {exc}")]
    statuses: List[CheckpointStatus] = []
    for doc in docs:
        if public_key is None:
            statuses.append(CheckpointStatus(doc.get("created_at", "?"), doc["records"], doc["key_id"], None))
            continue
        res: CheckpointResult = verify_checkpoint(state.log, doc, public_key)
        statuses.append(CheckpointStatus(res.created_at, res.records, doc["key_id"], res.ok,
                                         res.error or f"{res.records_since} record(s) added since"))
    return statuses


# ------------------------------------------------------------------------ health

@dataclass
class Finding:
    level: str      # "ok" | "warn" | "bad"
    text: str


def _age(seconds: float) -> str:
    if seconds < 90:
        return f"{int(seconds)} s"
    if seconds < 5400:
        return f"{int(seconds // 60)} min"
    if seconds < 2 * DAY:
        return f"{seconds / 3600:.1f} h"
    return f"{seconds / DAY:.1f} days"


def assess_health(a: Analysis, *, stale_checkpoint_days: float = 7.0,
                  window_seconds: float = DAY) -> List[Finding]:
    """Short, actionable list of findings. Any 'bad' means the exit code should be non-zero."""
    out: List[Finding] = []
    now = a.generated_at

    if a.log_check.ok:
        out.append(Finding("ok", f"Event log chain intact ({a.log_check.records} records)."))
    else:
        out.append(Finding("bad", f"Event log chain BROKEN: {a.log_check.error}. "
                                  "Preserve the file as evidence."))

    if a.inventory:
        out.append(Finding("ok", f"Baseline inventory: {a.inventory['files']} files, "
                                 f"created {a.inventory['created_at']}."))
    elif a.inventory_error:
        out.append(Finding("bad", a.inventory_error))
    else:
        out.append(Finding("warn", "No baseline inventory yet: run 'bastion inventory FOLDER'."))

    if a.sessions:
        last = a.sessions[-1]
        if last.ended_cleanly:
            out.append(Finding("warn", f"The monitor is not running (stopped {_age(now - (last.stop or now))} ago)."))
        else:
            quiet = now - last.last_seen
            out.append(Finding("ok", f"Monitor session started {_age(now - last.start)} ago "
                                     f"(last log activity {_age(quiet)} ago; "
                                     "if the process is gone, it stopped without a clean shutdown)."))
        unclean = sum(1 for g in a.gaps if g.after_unclean_stop)
        if unclean:
            out.append(Finding("warn", f"{unclean} monitor session(s) ended without a clean stop "
                                       "(crash, kill or power loss): see the coverage gaps in the report."))
    else:
        out.append(Finding("warn", "The real-time monitor has never run for this state."))

    recent = a.alerts_since(now - window_seconds)
    high = sum(1 for x in recent if x.get("severity") == "high")
    medium = sum(1 for x in recent if x.get("severity") == "medium")
    if high:
        out.append(Finding("bad", f"{high} high-severity alert(s) in the last {_age(window_seconds)}: "
                                  "review them with 'bastion events --alerts'."))
    if medium:
        out.append(Finding("warn", f"{medium} medium-severity alert(s) in the last {_age(window_seconds)}."))
    if not recent:
        out.append(Finding("ok", f"No alerts in the last {_age(window_seconds)}."))

    if a.canaries:
        out.append(Finding("ok", f"{a.canaries} canary file(s) deployed."))
    else:
        out.append(Finding("warn", "No canary files: 'bastion canary create FOLDER' adds a cheap early signal."))

    if a.checkpoints:
        newest = a.checkpoints[-1]
        bad = [c for c in a.checkpoints if c.ok is False]
        if bad:
            out.append(Finding("bad", f"{len(bad)} signed checkpoint(s) do NOT verify against the log: {bad[0].detail}"))
        else:
            verified = "all verified" if all(c.ok for c in a.checkpoints) else "not verified (no public key given)"
            out.append(Finding("ok", f"{len(a.checkpoints)} signed checkpoint(s), {verified}; newest {newest.created_at}."))
        stamp = _parse_iso(newest.created_at)
        if stamp is not None and now - stamp > stale_checkpoint_days * DAY:
            out.append(Finding("warn", f"The newest checkpoint is older than {stale_checkpoint_days:g} days: "
                                       "create a new one with 'bastion log checkpoint'."))
    else:
        out.append(Finding("warn", "No signed checkpoints: without one, someone who can rewrite the log "
                                   "can rebuild its hash chain unnoticed ('bastion sign keygen' then "
                                   "'bastion log checkpoint')."))
    return out


def _parse_iso(text: str) -> Optional[float]:
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def overall_ok(findings: List[Finding]) -> bool:
    return not any(f.level == "bad" for f in findings)


# ------------------------------------------------------------------------ Markdown

def _md(text: Any) -> str:
    """Escape text for a Markdown table cell / inline use."""
    s = str(text).replace("\\", "\\\\").replace("|", "\\|").replace("`", "'")
    return s.replace("\r", " ").replace("\n", " ")


def render_markdown(a: Analysis) -> str:
    lines = [
        "# Bastion incident report",
        "",
        f"_Generated {iso_utc(a.generated_at)} by Bastion {__version__}._",
        "",
        f"> {DISCLAIMER}",
        "",
        "## Evidence integrity",
        "",
        f"- Event log: **{'intact' if a.log_check.ok else 'BROKEN'}** ({a.log_check.records} records)"
        + ("" if a.log_check.ok else f" — {_md(a.log_check.error)}"),
        f"- Log head hash: `{a.log_check.head}`",
    ]
    if a.inventory:
        lines.append(f"- Baseline inventory root hash: `{a.inventory['root_hash']}` "
                     f"({a.inventory['files']} files, {a.inventory['created_at']})")
    if a.checkpoints:
        for c in a.checkpoints:
            state = {True: "verified", False: "**FAILED**", None: "not verified"}[c.ok]
            lines.append(f"- Checkpoint {_md(c.created_at)} covering {c.records} records: {state} {_md(c.detail)}")
    else:
        lines.append("- No signed checkpoints.")
    lines += ["", "## Summary", "",
              f"- Events recorded: {a.total_events} "
              + (f"({', '.join(f'{k}: {v}' for k, v in sorted(a.event_counts.items()))})" if a.event_counts else ""),
              f"- Alerts: {len(a.alerts)} (high {a.severity_counts.get('high', 0)}, "
              f"medium {a.severity_counts.get('medium', 0)}, low {a.severity_counts.get('low', 0)})"]
    if a.first_ts and a.last_ts:
        lines.append(f"- Period covered by the log: {iso_utc(a.first_ts)} to {iso_utc(a.last_ts)}")
    lines += ["", "## Alerts", ""]
    if not a.alerts:
        lines.append("No alerts recorded.")
    for alert in a.alerts[:MAX_ALERTS_IN_REPORT]:
        lines += [
            f"### [{_md(str(alert.get('severity', '?')).upper())}] {_md(alert.get('title', ''))} "
            f"(`{_md(alert.get('rule', ''))}`, {_md(alert.get('time', ''))})",
            "",
            f"- Observed: {_md(alert.get('explanation', ''))}",
            f"- Could be legitimate if: {_md(alert.get('benign_causes', ''))}",
            f"- Suggested check: {_md(alert.get('suggestion', ''))}",
            "",
        ]
    if len(a.alerts) > MAX_ALERTS_IN_REPORT:
        lines.append(f"_{len(a.alerts) - MAX_ALERTS_IN_REPORT} more alert(s) omitted; see the log._")
    if a.top_dirs:
        lines += ["", "## Most active folders", "", "| Folder | Events |", "|---|---|"]
        lines += [f"| {_md(p)} | {n} |" for p, n in a.top_dirs]
    lines += ["", "## Monitoring coverage", ""]
    if a.sessions:
        lines += ["| Started (UTC) | Stopped (UTC) | Alerts |", "|---|---|---|"]
        for s in a.sessions:
            lines.append(f"| {iso_utc(s.start)} | {iso_utc(s.stop) if s.stop else 'no clean stop'} | {s.alerts} |")
    else:
        lines.append("The real-time monitor never ran.")
    for g in a.gaps:
        lines.append(f"\n- Gap of {_age(g.seconds)} with no monitor ({iso_utc(g.start)} to {iso_utc(g.end)})"
                     + (" after an unclean stop." if g.after_unclean_stop else "."))
    lines += ["", "## What this report cannot tell you", "",
              "- It reports signals, not verdicts: every alert lists possible legitimate causes.",
              "- Anything that happened while no monitor was running is invisible here.",
              "- A log on a compromised machine can be deleted; keep signed checkpoints and the "
              "log head hash somewhere else.", ""]
    return "\n".join(lines)


# --------------------------------------------------------------------------- HTML

_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#14181f;--muted:#5b6573;--line:#dde1e7;--accent:#2457c5;
--high:#b3261e;--med:#8a5a00;--low:#1d6b73;--ok:#1d6b3b;--bad-bg:#fdecea;--warn-bg:#fff5e0;--ok-bg:#e8f5ec;
--bar:#9db5e8;--bar-alert:#b3261e}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--card:#171c23;--ink:#e6e9ee;--muted:#9aa4b2;
--line:#2a313b;--accent:#8fb0ff;--high:#ff8a80;--med:#f2c46d;--low:#6fd0d9;--ok:#7bd89a;
--bad-bg:#3a1a18;--warn-bg:#3a2f14;--ok-bg:#16301f;--bar:#4a6194;--bar-alert:#ff8a80}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.15rem;margin:32px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
.sub{color:var(--muted);margin:0 0 16px}.note{background:var(--card);border:1px solid var(--line);
border-left:4px solid var(--accent);padding:10px 14px;border-radius:6px;color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card b{display:block;font-size:1.5rem}.card span{color:var(--muted);font-size:.85rem}
.pill{display:inline-block;padding:1px 9px;border-radius:99px;font-size:.78rem;font-weight:600;border:1px solid currentColor}
.high{color:var(--high)}.medium{color:var(--med)}.low{color:var(--low)}.ok{color:var(--ok)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top;font-size:.9rem}
th{color:var(--muted);font-weight:600}tr:last-child td{border-bottom:0}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.85em;word-break:break-all}
details.alert{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:8px 0;padding:0 14px}
details.alert summary{cursor:pointer;padding:10px 0;font-weight:600}
details.alert .body{padding:0 0 12px}.kv{margin:4px 0}.kv b{color:var(--muted);font-weight:600}
.box{padding:9px 13px;border-radius:6px;margin:6px 0}.box.bad{background:var(--bad-bg)}
.box.warn{background:var(--warn-bg)}.box.ok{background:var(--ok-bg)}
svg{width:100%;height:auto;background:var(--card);border:1px solid var(--line);border-radius:8px}
.bar{fill:var(--bar)}.abar{fill:var(--bar-alert)}.axis{fill:var(--muted);font-size:10px}
footer{margin-top:40px;color:var(--muted);font-size:.85rem}
@media print{body{background:#fff;color:#000}details.alert{break-inside:avoid}}
"""


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _timeline_svg(tl: Optional[Timeline]) -> str:
    if tl is None:
        return "<p class='sub'>No events recorded.</p>"
    n = len(tl.events)
    width, height, left, bottom = 720, 160, 8, 22
    plot_h = height - bottom - 8
    peak = max(max(tl.events), max(tl.alerts), 1)
    slot = (width - left * 2) / n
    bar_w = max(slot - 2, 1)
    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" '
             f'aria-label="Events and alerts over time, {n} intervals of {tl.bucket_seconds} seconds">']
    for i, (ev, al) in enumerate(zip(tl.events, tl.alerts, strict=True)):
        x = left + i * slot
        start = iso_utc(tl.start + i * tl.bucket_seconds)
        h = plot_h * ev / peak
        parts.append(f'<rect class="bar" x="{x:.1f}" y="{8 + plot_h - h:.1f}" width="{bar_w:.1f}" '
                     f'height="{h:.1f}"><title>{_e(start)}: {ev} event(s), {al} alert(s)</title></rect>')
        if al:
            parts.append(f'<rect class="abar" x="{x:.1f}" y="{height - bottom + 2}" width="{bar_w:.1f}" '
                         f'height="4"><title>{_e(start)}: {al} alert(s)</title></rect>')
    parts.append(f'<text class="axis" x="{left}" y="{height - 4}">{_e(iso_utc(tl.start))}</text>')
    parts.append(f'<text class="axis" x="{width - left}" y="{height - 4}" text-anchor="end">'
                 f'interval = {tl.bucket_seconds} s · peak {peak} event(s)</text>')
    parts.append("</svg>")
    return "".join(parts)


def _alert_html(alert: Dict[str, Any]) -> str:
    sev = str(alert.get("severity", "low"))
    sev_class = sev if sev in SEVERITIES else "low"
    related = alert.get("events", [])[:MAX_RELATED_IN_REPORT]
    rows = ""
    if related:
        rows = ("<table><tr><th>Time (UTC)</th><th>Type</th><th>Path</th><th>Entropy</th></tr>"
                + "".join(
                    f"<tr><td class='mono'>{_e(e.get('time', ''))}</td><td>{_e(e.get('type', ''))}</td>"
                    f"<td class='mono'>{_e(e.get('path', ''))}"
                    + (f" → {_e(e['dest_path'])}" if e.get("dest_path") else "")
                    + f"</td><td>{_e(e.get('entropy', ''))}</td></tr>" for e in related)
                + "</table>")
        total = alert.get("total_related", len(related))
        if total > len(related):
            rows += f"<p class='sub'>Showing {len(related)} of {_e(total)} related events.</p>"
    return (
        f"<details class='alert'><summary><span class='pill {sev_class}'>{_e(sev.upper())}</span> "
        f"{_e(alert.get('title', ''))} <span class='sub'>· {_e(alert.get('rule', ''))} · "
        f"{_e(alert.get('time', ''))}</span></summary><div class='body'>"
        f"<p class='kv'><b>Observed:</b> {_e(alert.get('explanation', ''))}</p>"
        f"<p class='kv'><b>Could be legitimate if:</b> {_e(alert.get('benign_causes', ''))}</p>"
        f"<p class='kv'><b>Suggested check:</b> {_e(alert.get('suggestion', ''))}</p>{rows}</div></details>"
    )


def _checkpoint_card(a: Analysis) -> Tuple[str, str]:
    if not a.checkpoints:
        return "none", "medium"
    if any(c.ok is False for c in a.checkpoints):
        return "FAILED", "high"
    if all(c.ok for c in a.checkpoints):
        return "verified", "ok"
    return f"{len(a.checkpoints)} (unverified)", "medium"


def render_html(a: Analysis, findings: Optional[List[Finding]] = None) -> str:
    findings = findings if findings is not None else assess_health(a)
    sev = a.severity_counts
    log_state = "intact" if a.log_check.ok else "BROKEN"
    log_class = "ok" if a.log_check.ok else "high"
    cp_label, cp_class = _checkpoint_card(a)
    out: List[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<meta name='color-scheme' content='light dark'>",
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">",
        "<title>Bastion incident report</title>",
        f"<style>{_CSS}</style></head><body><main>",
        "<h1>Bastion incident report</h1>",
        f"<p class='sub'>Generated {_e(iso_utc(a.generated_at))} · Bastion {_e(__version__)} · "
        f"state: <span class='mono'>{_e(a.state_dir)}</span></p>",
        f"<p class='note'>{_e(DISCLAIMER)} This report lists signals and evidence; it does not "
        "identify a cause or an actor.</p>",
        "<div class='cards'>",
        f"<div class='card'><b>{a.total_events}</b><span>events recorded</span></div>",
        f"<div class='card'><b class='high'>{sev.get('high', 0)}</b><span>high alerts</span></div>",
        f"<div class='card'><b class='medium'>{sev.get('medium', 0)}</b><span>medium alerts</span></div>",
        f"<div class='card'><b class='{log_class}'>{log_state}</b><span>log hash chain</span></div>",
        f"<div class='card'><b class='{cp_class}'>{_e(cp_label)}</b><span>signed checkpoints</span></div>",
        "</div>",
        "<h2>Health</h2>",
    ]
    out += [f"<div class='box {_e(f.level)}'>{_e(f.text)}</div>" for f in findings]

    out += ["<h2>Evidence integrity</h2><table>",
            f"<tr><th>Log head hash</th><td class='mono'>{_e(a.log_check.head)}</td></tr>",
            f"<tr><th>Log records</th><td>{a.log_check.records}</td></tr>"]
    if a.inventory:
        out.append(f"<tr><th>Baseline root hash</th><td class='mono'>{_e(a.inventory['root_hash'])}</td></tr>"
                   f"<tr><th>Baseline</th><td>{_e(a.inventory['files'])} files · created "
                   f"{_e(a.inventory['created_at'])} · <span class='mono'>{_e(a.inventory['root'])}</span></td></tr>")
    out.append("</table>")
    if a.checkpoints:
        out.append("<h2>Signed checkpoints</h2><table><tr><th>Created</th><th>Records covered</th>"
                   "<th>Key</th><th>Result</th></tr>")
        for c in a.checkpoints:
            label = {True: "<span class='ok'>verified</span>", False: "<span class='high'>FAILED</span>",
                     None: "not verified (public key not supplied)"}[c.ok]
            out.append(f"<tr><td>{_e(c.created_at)}</td><td>{c.records}</td>"
                       f"<td class='mono'>{_e(c.key_id[:16])}</td><td>{label} {_e(c.detail)}</td></tr>")
        out.append("</table>")

    out += ["<h2>Timeline</h2>", _timeline_svg(a.timeline)]

    out.append(f"<h2>Alerts ({len(a.alerts)})</h2>")
    if not a.alerts:
        out.append("<p class='sub'>No alerts recorded.</p>")
    for alert in a.alerts[:MAX_ALERTS_IN_REPORT]:
        out.append(_alert_html(alert))
    if len(a.alerts) > MAX_ALERTS_IN_REPORT:
        out.append(f"<p class='sub'>{len(a.alerts) - MAX_ALERTS_IN_REPORT} more alert(s) omitted; see the log.</p>")
    if a.rule_counts:
        out.append("<h2>Alerts by rule</h2><table><tr><th>Rule</th><th>Alerts</th></tr>"
                   + "".join(f"<tr><td>{_e(r)}</td><td>{n}</td></tr>"
                             for r, n in sorted(a.rule_counts.items(), key=lambda kv: -kv[1]))
                   + "</table>")
    if a.top_dirs:
        out.append("<h2>Most active folders</h2><table><tr><th>Folder</th><th>Events</th></tr>"
                   + "".join(f"<tr><td class='mono'>{_e(p)}</td><td>{n}</td></tr>" for p, n in a.top_dirs)
                   + "</table>")

    out.append("<h2>Monitoring coverage</h2>")
    if a.sessions:
        out.append("<table><tr><th>Monitor started (UTC)</th><th>Stopped (UTC)</th><th>Alerts</th></tr>")
        for s in a.sessions:
            stop = _e(iso_utc(s.stop)) if s.stop else "<span class='medium'>no clean stop recorded</span>"
            out.append(f"<tr><td class='mono'>{_e(iso_utc(s.start))}</td><td class='mono'>{stop}</td>"
                       f"<td>{s.alerts}</td></tr>")
        out.append("</table>")
        for g in a.gaps:
            out.append(f"<div class='box warn'>No monitor was running for {_e(_age(g.seconds))} "
                       f"({_e(iso_utc(g.start))} to {_e(iso_utc(g.end))})"
                       + (" after a session that did not stop cleanly." if g.after_unclean_stop else ".")
                       + " Changes in that period were not observed in real time; use <code>bastion verify</code>"
                         " to compare against the baseline.</div>")
    else:
        out.append("<p class='sub'>The real-time monitor never ran for this state.</p>")

    out += ["<h2>What this report cannot tell you</h2><ul>",
            "<li>Whether activity was malicious: every alert lists legitimate causes to rule out first.</li>",
            "<li>Anything that happened while no monitor was running.</li>",
            "<li>Whether the log is complete after the last signed checkpoint, or untouched if the "
            "machine was fully compromised: keep checkpoints and hashes somewhere else.</li></ul>",
            "<footer>Self-contained report: no scripts and no external resources. "
            "Treat it as sensitive: it contains file names from the monitored folder.</footer>",
            "</main></body></html>"]
    return "\n".join(out)


def write_report(path: Path, content: str) -> Path:
    """Write a report atomically; never overwrites an existing file."""
    path = Path(path)
    if path.exists():
        raise BastionError(f"{path} already exists; reports are never overwritten. Choose another name.")
    atomic_write_bytes(path, content.encode("utf-8"), mode=0o600)
    return path
