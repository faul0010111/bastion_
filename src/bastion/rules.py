"""Rule engine: sliding windows over file events.

Each rule counts *distinct* files inside a time window. The engine is
deterministic (it uses the event's timestamp, not the wall clock), which makes
it easy to test. Alerts describe what was observed, possible legitimate causes
and what to check, without claiming the activity is malicious.
"""

from __future__ import annotations

from collections import Counter, deque
from pathlib import PurePosixPath
from typing import Callable, Deque, Dict, Iterable, List, Optional, Set, Tuple

from .config import EntropySettings, HeaderSettings, NoteSettings, RulesConfig, RuleSettings
from .events import Alert, Event
from .filetypes import lost_known_header

PER_EVENT_RULES = (
    "canary_touched",
    "mass_modification",
    "mass_rename",
    "mass_deletion",
    "extension_change",
    "entropy_spike",
    "header_lost",
)
# Rules that count distinct files *per group* (same new extension, same note content).
GROUPED_RULES = ("uniform_extension", "note_dropped")
MAX_RELATED_EVENTS = 20

_META: Dict[str, Dict[str, str]] = {
    "mass_modification": {
        "severity": "medium",
        "title": "Many files modified in a short time",
        "what": "{observed} distinct files were modified within {window} (rule threshold: {threshold}).",
        "benign": "software updates, reindexing, builds, cloud sync or a backup restore.",
        "suggestion": "Identify which program or user is writing these files and run 'bastion verify' to compare against the inventory.",
    },
    "mass_rename": {
        "severity": "medium",
        "title": "Many files renamed in a short time",
        "what": "{observed} distinct files were renamed/moved within {window} (rule threshold: {threshold}).",
        "benign": "folder reorganization, bulk-rename tools or a planned migration.",
        "suggestion": "Check whether someone ran a planned reorganization. If not, validate the latest backup with 'bastion backup validate'.",
    },
    "mass_deletion": {
        "severity": "medium",
        "title": "Many files deleted in a short time",
        "what": "{observed} distinct files were deleted within {window} (rule threshold: {threshold}).",
        "benign": "cleanup of temporary folders, an uninstall or a planned archive job.",
        "suggestion": "Check the recycle bin and the latest backup before doing anything else.",
    },
    "extension_change": {
        "severity": "medium",
        "title": "Many file extensions changed",
        "what": "{observed} distinct files had their extension changed within {window} (rule threshold: {threshold}).",
        "benign": "bulk format conversion or organizing tools.",
        "suggestion": "Look at which new extensions appeared and whether the same one repeats across many files.",
    },
    "entropy_spike": {
        "severity": "high",
        "title": "Files started to look like random data",
        "what": ("{observed} distinct files had a sharp jump in content entropy within {window} "
                 "(rule threshold: {threshold}). Encrypted or compressed content has entropy close to 8 bits/byte."),
        "benign": "bulk compression, exports to compressed formats, or encryption you performed on purpose.",
        "suggestion": "If you did not start any compression or encryption, disconnect the machine from the network and contact whoever handles security before deleting or rebooting anything.",
    },
    "header_lost": {
        "severity": "high",
        "title": "Files lost their recognizable format header",
        "what": ("{observed} distinct files that used to start with a known format header "
                 "(PDF, ZIP/Office, JPEG...) now look like unstructured high-entropy data "
                 "within {window} (rule threshold: {threshold}). This catches content "
                 "replacement in files that were already compressed, where an entropy jump "
                 "cannot be seen."),
        "benign": "a tool that rewrote files in a proprietary or encrypted-on-purpose format, or a broken export.",
        "suggestion": "Open one of the listed files: if it no longer opens in its normal program, stop writing to this folder and check the latest backup with 'bastion backup validate'.",
    },
    "uniform_extension": {
        "severity": "medium",
        "title": "Many files now share the same new extension",
        "what": ("{observed} distinct files were renamed to the same new extension "
                 "'{detail}' within {window} (rule threshold: {threshold})."),
        "benign": "a bulk format conversion or an archive/export tool that tags its output.",
        "suggestion": "Check whether the extension belongs to a program you use. An unknown extension appended to many files deserves a closer look.",
    },
    "note_dropped": {
        "severity": "high",
        "title": "The same file appeared in many different folders",
        "what": ("An identical small file ('{detail}') was created in {observed} distinct folders "
                 "within {window} (rule threshold: {threshold})."),
        "benign": "project scaffolding, unpacking an archive that ships a README/LICENSE in every folder, or a sync client.",
        "suggestion": "Read one of the files. If you did not create them and they contain instructions or messages, do not follow them; keep the files as evidence and review the other alerts.",
    },
    "canary_touched": {
        "severity": "high",
        "title": "A canary file was touched",
        "what": "A canary file (one that nobody should open or change) was modified, renamed or deleted.",
        "benign": "someone opened and saved the canary file by accident, or a scan/indexer touched it.",
        "suggestion": "Find out who or what touched it. If it is unknown, treat it as possible unauthorized activity and review the other events.",
    },
    "correlated_signals": {
        "severity": "high",
        "title": "Several independent signals coincided",
        "what": ("{observed} different rules fired within {window}: {rules}. "
                 "Independent signals coinciding raises the priority of the analysis, but does not prove the cause."),
        "benign": "large legitimate operations (migration, restore, update) can trigger several rules at once.",
        "suggestion": "Treat this as an analysis priority: review the individual alerts and their related events.",
    },
}


def _suffix(path: str) -> str:
    return PurePosixPath(path).suffix.lower()


def _canary_hit(ev: Event, _s: RuleSettings, canaries: Set[str]) -> bool:
    if ev.type == "created" or not canaries:
        return False
    return ev.path in canaries or (ev.dest_path in canaries if ev.dest_path else False)


def _entropy_hit(ev: Event, s: RuleSettings, _c: Set[str]) -> bool:
    assert isinstance(s, EntropySettings)
    if ev.type not in ("modified", "moved"):
        return False
    if ev.entropy is None or ev.prev_entropy is None or (ev.size or 0) < s.min_size_bytes:
        return False
    return ev.entropy >= s.min_entropy and (ev.entropy - ev.prev_entropy) >= s.min_delta


def _header_hit(ev: Event, s: RuleSettings, _c: Set[str]) -> bool:
    assert isinstance(s, HeaderSettings)
    if ev.type not in ("modified", "moved"):
        return False
    if (ev.size or 0) < s.min_size_bytes or ev.entropy is None or ev.entropy < s.min_entropy:
        return False
    return lost_known_header(ev.prev_magic, ev.magic)


def _parent(path: str) -> str:
    return PurePosixPath(path).parent.as_posix()


def _group_extension(ev: Event, _s: RuleSettings) -> Optional[Tuple[str, str]]:
    """(group, distinct-key) for moves that give a file a different, non-empty extension."""
    if ev.type != "moved" or ev.dest_path is None:
        return None
    new, old = _suffix(ev.dest_path), _suffix(ev.path)
    if not new or new == old:
        return None
    return new, ev.path


def _group_note(ev: Event, s: RuleSettings) -> Optional[Tuple[str, str]]:
    """(content hash, folder) for small identical files created in a folder."""
    assert isinstance(s, NoteSettings)
    if ev.type != "created" or not ev.sha256 or ev.size is None:
        return None
    if not (s.min_size_bytes <= ev.size <= s.max_size_bytes):
        return None
    return ev.sha256, _parent(ev.affected_path)


_GROUPERS: Dict[str, Callable[[Event, RuleSettings], Optional[Tuple[str, str]]]] = {
    "uniform_extension": _group_extension,
    "note_dropped": _group_note,
}


_MATCHERS: Dict[str, Callable[[Event, RuleSettings, Set[str]], bool]] = {
    "canary_touched": _canary_hit,
    "mass_modification": lambda ev, s, c: ev.type == "modified",
    "mass_rename": lambda ev, s, c: ev.type == "moved",
    "mass_deletion": lambda ev, s, c: ev.type == "deleted",
    "extension_change": lambda ev, s, c: (
        ev.type == "moved" and ev.dest_path is not None and _suffix(ev.path) != _suffix(ev.dest_path)),
    "entropy_spike": _entropy_hit,
    "header_lost": _header_hit,
}


class _Window:
    def __init__(self) -> None:
        self.items: Deque[Tuple[float, str, Event]] = deque()
        self.counts: Counter = Counter()

    def add(self, ts: float, key: str, ev: Event) -> None:
        self.items.append((ts, key, ev))
        self.counts[key] += 1

    def evict(self, cutoff: float) -> None:
        while self.items and self.items[0][0] < cutoff:
            _, key, _ = self.items.popleft()
            self.counts[key] -= 1
            if self.counts[key] <= 0:
                del self.counts[key]

    def distinct(self) -> int:
        return len(self.counts)

    def related(self) -> Tuple[List[Event], int]:
        latest: Dict[str, Event] = {}
        for _, key, ev in self.items:
            latest[key] = ev
        evs = sorted(latest.values(), key=lambda e: e.ts)
        return evs[:MAX_RELATED_EVENTS], len(evs)


def _short_note_name(related: List[Event]) -> str:
    return PurePosixPath(related[0].affected_path).name if related else "?"


def _fmt_window(seconds: float) -> str:
    return f"{seconds:g} s"


class RuleEngine:
    def __init__(self, config: RulesConfig, canary_paths: Iterable[str] = ()) -> None:
        self.config = config
        self.canaries: Set[str] = set(canary_paths)
        self._windows: Dict[str, _Window] = {name: _Window() for name in PER_EVENT_RULES}
        self._grouped: Dict[str, Dict[str, _Window]] = {name: {} for name in GROUPED_RULES}
        self._last_alert: Dict[str, float] = {}

    def _cooling(self, rule: str, now: float) -> bool:
        last = self._last_alert.get(rule)
        return last is not None and (now - last) < self.config.cooldown_seconds

    def _alert(self, rule: str, ts: float, s: RuleSettings, observed: int,
               events: List[Event], total: int, rules_text: str = "",
               detail: str = "") -> Alert:
        meta = _META[rule]
        what = meta["what"].format(observed=observed, window=_fmt_window(s.window_seconds),
                                   threshold=s.threshold, rules=rules_text, detail=detail)
        return Alert(
            rule=rule, severity=meta["severity"], title=meta["title"], explanation=what,
            benign_causes=meta["benign"], suggestion=meta["suggestion"], ts=ts,
            threshold=s.threshold, observed=observed, window_seconds=s.window_seconds,
            events=[e.to_dict() for e in events], total_related=total,
        )

    def process(self, event: Event) -> List[Alert]:
        now = event.ts
        alerts: List[Alert] = []
        for name in PER_EVENT_RULES:
            settings = self.config.rules[name]
            if not settings.enabled or not _MATCHERS[name](event, settings, self.canaries):
                continue
            window = self._windows[name]
            window.add(now, event.path, event)
            window.evict(now - settings.window_seconds)
            observed = window.distinct()
            if observed >= settings.threshold and not self._cooling(name, now):
                related, total = window.related()
                alerts.append(self._alert(name, now, settings, observed, related, total))
                self._last_alert[name] = now
        alerts.extend(self._process_grouped(event))
        if alerts:
            corr = self._correlate(now)
            if corr:
                alerts.append(corr)
        return alerts

    def _process_grouped(self, event: Event) -> List[Alert]:
        now = event.ts
        alerts: List[Alert] = []
        for name in GROUPED_RULES:
            settings = self.config.rules[name]
            if not settings.enabled:
                continue
            grouped = _GROUPERS[name](event, settings)
            groups = self._grouped[name]
            if grouped is not None:
                group, distinct_key = grouped
                window = groups.setdefault(group, _Window())
                window.add(now, distinct_key, event)
                window.evict(now - settings.window_seconds)
                observed = window.distinct()
                if observed >= settings.threshold and not self._cooling(name, now):
                    related, total = window.related()
                    detail = group if name == "uniform_extension" else _short_note_name(related)
                    alerts.append(self._alert(name, now, settings, observed, related, total,
                                              detail=detail))
                    self._last_alert[name] = now
            self._prune(groups, now - settings.window_seconds)
        return alerts

    @staticmethod
    def _prune(groups: Dict[str, "_Window"], cutoff: float) -> None:
        """Drop groups whose window is empty so memory stays bounded."""
        for key in list(groups):
            groups[key].evict(cutoff)
            if not groups[key].items:
                del groups[key]

    def process_many(self, events: Iterable[Event]) -> List[Alert]:
        out: List[Alert] = []
        for ev in events:
            out.extend(self.process(ev))
        return out

    def _correlate(self, now: float) -> Optional[Alert]:
        name = "correlated_signals"
        s = self.config.rules[name]
        if not s.enabled or self._cooling(name, now):
            return None
        recent = sorted(r for r, t in self._last_alert.items()
                        if r != name and t >= now - s.window_seconds)
        if len(recent) < s.threshold:
            return None
        self._last_alert[name] = now
        return self._alert(name, now, s, len(recent), [], 0, rules_text=", ".join(recent))
