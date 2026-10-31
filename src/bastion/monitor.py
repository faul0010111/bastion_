"""Real-time monitoring.

``EventProcessor`` turns raw filesystem notifications into ``Event`` objects
(with hash and entropy), records them in the log and runs them through the rule
engine. It does not depend on watchdog, so it can be tested with real file
operations. ``Monitor`` connects the processor to a watchdog observer.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Callable, Dict, List, NamedTuple, Optional

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver
from watchdog.observers.polling import PollingObserver

from .canary import load_canaries
from .config import RulesConfig, StatePaths
from .eventlog import EventLog
from .events import Alert, Event
from .fingerprint import Fingerprint, fingerprint_file, is_regular_file
from .inventory import Inventory, load_inventory, save_inventory, scan_directory
from .paths import is_ignored, to_relative_posix
from .rules import RuleEngine

NOT_REGULAR_NOTE = "not a regular file (ignored)"


class IndexEntry(NamedTuple):
    sha256: str
    entropy: float
    magic: str = ""


def index_from_inventory(inv: Inventory) -> Dict[str, IndexEntry]:
    return {p: IndexEntry(e.sha256, e.entropy, e.magic) for p, e in inv.entries.items()}


class EventProcessor:
    def __init__(
        self,
        root: Path,
        engine: RuleEngine,
        config: RulesConfig,
        log: Optional[EventLog] = None,
        index: Optional[Dict[str, IndexEntry]] = None,
        on_event: Optional[Callable[[Event], None]] = None,
        on_alert: Optional[Callable[[Alert], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.root = root
        self.engine = engine
        self.ignore = tuple(config.ignore_patterns)
        self.log = log
        self.index: Dict[str, IndexEntry] = index if index is not None else {}
        self.on_event, self.on_alert, self.on_error = on_event, on_alert, on_error
        self.clock = clock
        self.last_activity = clock()
        self.alerts: List[Alert] = []

    # -- input ---------------------------------------------------------------
    def handle(self, kind: str, src: str, dest: Optional[str] = None) -> Optional[Event]:
        """Process a raw notification ('created', 'modified', 'deleted', 'moved')."""
        self.last_activity = self.clock()
        rel_src = to_relative_posix(src, self.root)
        rel_dest = to_relative_posix(dest, self.root) if dest else None
        if kind == "moved":
            keep_src = rel_src if rel_src is not None and not is_ignored(rel_src, self.ignore) else None
            keep_dest = rel_dest if rel_dest is not None and not is_ignored(rel_dest, self.ignore) else None
            if keep_src is not None and keep_dest is not None:
                return self._moved(keep_src, keep_dest)
            if keep_dest is not None:   # "save via temp file" pattern: becomes a modification/creation
                return self._content_event("modified" if keep_dest in self.index else "created", keep_dest)
            if keep_src is not None:    # file moved out (or to an ignored name)
                return self._deleted(keep_src)
            return None
        if rel_src is None or is_ignored(rel_src, self.ignore):
            return None
        if kind in ("created", "modified"):
            return self._content_event(kind, rel_src)
        if kind == "deleted":
            return self._deleted(rel_src)
        return None

    # -- event construction ----------------------------------------------------
    def _read(self, rel: str) -> "tuple[Optional[Fingerprint], Optional[str]]":
        full = self.root / rel
        if not is_regular_file(full):
            if os.path.lexists(full):
                return None, NOT_REGULAR_NOTE
            return None, "file removed before it could be read"
        try:
            return fingerprint_file(full), None
        except FileNotFoundError:
            return None, "file removed before it could be read"
        except PermissionError:
            return None, "no permission to read the file"
        except OSError as exc:
            return None, f"read error: {exc.strerror or exc}"

    def _content_event(self, kind: str, rel: str) -> Optional[Event]:
        fp, note = self._read(rel)
        if note == NOT_REGULAR_NOTE:
            return None
        prev = self.index.get(rel)
        if kind == "created" and prev is not None:
            # Some observers (e.g. macOS FSEvents) keep reporting "created" for a path that
            # was created shortly before; a path already in the index is a modification.
            kind = "modified"
        if kind == "modified" and fp and prev and prev.sha256 == fp.sha256:
            return None  # no content change (duplicate event or metadata only)
        ev = Event(kind, rel, self.clock(), sha256=fp.sha256 if fp else None,
                   size=fp.size if fp else None, entropy=fp.entropy if fp else None,
                   prev_entropy=prev.entropy if prev else None,
                   magic=fp.magic if fp else None, prev_magic=prev.magic if prev else None,
                   note=note)
        if fp:
            self.index[rel] = IndexEntry(fp.sha256, fp.entropy, fp.magic)
        return self._emit(ev)

    def _moved(self, rel_src: str, rel_dest: str) -> Optional[Event]:
        fp, note = self._read(rel_dest)
        if note == NOT_REGULAR_NOTE:
            return None
        prev = self.index.pop(rel_src, None)
        ev = Event("moved", rel_src, self.clock(), dest_path=rel_dest,
                   sha256=fp.sha256 if fp else (prev.sha256 if prev else None),
                   size=fp.size if fp else None, entropy=fp.entropy if fp else None,
                   prev_entropy=prev.entropy if prev else None,
                   magic=fp.magic if fp else None, prev_magic=prev.magic if prev else None,
                   note=note)
        if fp:
            self.index[rel_dest] = IndexEntry(fp.sha256, fp.entropy, fp.magic)
        return self._emit(ev)

    def _deleted(self, rel: str) -> Optional[Event]:
        self.index.pop(rel, None)
        return self._emit(Event("deleted", rel, self.clock()))

    # -- output ----------------------------------------------------------------
    def _emit(self, event: Event) -> Event:
        self._safe_log("event", event.to_dict())
        if self.on_event:
            self.on_event(event)
        for alert in self.engine.process(event):
            self.alerts.append(alert)
            self._safe_log("alert", alert.to_dict())
            if self.on_alert:
                self.on_alert(alert)
        return event

    def _safe_log(self, kind: str, data: dict) -> None:
        if not self.log:
            return
        try:
            self.log.append(kind, data)
        except OSError as exc:
            if self.on_error:
                self.on_error(f"failed to write to the log: {exc}")


class _Handler(FileSystemEventHandler):
    def __init__(self, processor: EventProcessor) -> None:
        self._p = processor

    def _run(self, kind: str, src: "str | bytes", dest: "str | bytes | None" = None) -> None:
        try:
            self._p.handle(kind, os.fsdecode(src), os.fsdecode(dest) if dest else None)
        except Exception as exc:  # the observer must not die because of one problematic file
            if self._p.on_error:
                self._p.on_error(f"error processing {kind} on {src!r}: {exc}")

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._run("created", event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._run("modified", event.src_path)

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._run("deleted", event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._run("moved", event.src_path, event.dest_path)


class Monitor:
    def __init__(
        self,
        root: Path,
        state: StatePaths,
        config: RulesConfig,
        *,
        polling: bool = False,
        on_event: Optional[Callable[[Event], None]] = None,
        on_alert: Optional[Callable[[Alert], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
        on_progress: Optional[Callable[[int], None]] = None,
    ) -> None:
        self.root, self.state, self.config = root, state, config
        self.polling = polling
        self.on_event, self.on_alert, self.on_error = on_event, on_alert, on_error
        self.on_progress = on_progress
        self.log: Optional[EventLog] = None
        self.processor: Optional[EventProcessor] = None
        self._observer: Optional[BaseObserver] = None
        self.baseline_created = False

    @property
    def alerts(self) -> List[Alert]:
        return self.processor.alerts if self.processor else []

    def start(self) -> None:
        self.state.ensure()
        inv = self._load_or_scan_baseline()
        self.log = EventLog(self.state.log)
        self.log.append("system", {"action": "monitor_start", "root": str(self.root),
                                   "baseline_root_hash": inv.root_hash(), "files": len(inv.entries)})
        engine = RuleEngine(self.config, load_canaries(self.state.canaries))
        self.processor = EventProcessor(
            self.root, engine, self.config, self.log, index_from_inventory(inv),
            self.on_event, self.on_alert, self.on_error)
        observer: BaseObserver = PollingObserver() if self.polling else Observer()
        observer.schedule(_Handler(self.processor), str(self.root), recursive=True)
        observer.start()
        self._observer = observer

    def _load_or_scan_baseline(self) -> Inventory:
        if self.state.inventory.exists():
            inv = load_inventory(self.state.inventory)
            if inv.root == str(self.root):
                return inv
        inv = scan_directory(self.root, self.config.ignore_patterns, self.on_progress)
        save_inventory(inv, self.state.inventory)
        self.baseline_created = True
        return inv

    def wait_idle(self, quiet_seconds: float = 1.0, timeout: float = 15.0) -> None:
        """Wait until no new events arrive for ``quiet_seconds`` (or until the timeout)."""
        assert self.processor is not None
        deadline = time.time() + timeout
        while time.time() < deadline:
            if time.time() - self.processor.last_activity >= quiet_seconds:
                return
            time.sleep(0.1)

    def stop(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        if self.log is not None:
            self.log.append("system", {"action": "monitor_stop", "alerts": len(self.alerts)})

    def __enter__(self) -> "Monitor":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()
