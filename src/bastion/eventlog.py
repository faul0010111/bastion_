"""Hash-chained event log (tamper-evident evidence).

Each JSON line carries the hash of the previous line. Editing, removing or
reordering records breaks the chain and ``verify_log`` points to where.

Honest limit: anyone with write access to the file can rebuild the whole
chain. That is why the "head" (hash of the last record) should be written down
off the machine; ``verify_log(anchor=...)`` checks that a previously noted hash
is still in the chain.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .errors import LogIntegrityError

GENESIS = "0" * 64
KINDS = ("event", "alert", "system")


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _record_hash(prev: str, seq: int, ts: float, kind: str, data: Dict[str, Any]) -> str:
    body = _canonical({"seq": seq, "ts": ts, "kind": kind, "data": data})
    return hashlib.sha256((prev + body).encode("utf-8")).hexdigest()


@dataclass
class LogVerification:
    ok: bool
    records: int
    head: str
    error: Optional[str] = None
    bad_seq: Optional[int] = None
    anchor_found: Optional[bool] = None


def verify_log(path: Path, anchor: Optional[str] = None) -> LogVerification:
    path = Path(path)
    if not path.exists():
        return LogVerification(True, 0, GENESIS, anchor_found=None if anchor is None else False)
    prev, count, found = GENESIS, 0, False
    try:
        with open(path, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                    seq, ts, kind, data = rec["seq"], rec["ts"], rec["kind"], rec["data"]
                    stored_prev, stored_hash = rec["prev"], rec["hash"]
                except (ValueError, KeyError, TypeError):
                    return LogVerification(False, count, prev, f"line {line_no} is unreadable", count + 1)
                if seq != count + 1:
                    return LogVerification(
                        False, count, prev,
                        f"expected sequence {count + 1}, found {seq} (record removed or reordered?)", seq)
                if stored_prev != prev:
                    return LogVerification(False, count, prev, f"record {seq}: link to previous record does not match", seq)
                if _record_hash(prev, seq, ts, kind, data) != stored_hash:
                    return LogVerification(False, count, prev, f"record {seq}: content was altered", seq)
                prev, count = stored_hash, count + 1
                if anchor and stored_hash == anchor:
                    found = True
    except (OSError, UnicodeDecodeError) as exc:
        return LogVerification(False, count, prev, f"read error: {exc}")
    return LogVerification(True, count, prev, anchor_found=(found if anchor else None))


def read_records(path: Path) -> Iterator[Dict[str, Any]]:
    """Read records without verifying the chain (use verify_log for that). Skips unreadable lines."""
    path = Path(path)
    if not path.exists():
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                yield json.loads(line)
            except ValueError:
                continue


def query_records(
    path: Path,
    *,
    kind: Optional[str] = None,
    event_type: Optional[str] = None,
    rule: Optional[str] = None,
    since: Optional[float] = None,
    until: Optional[float] = None,
    path_contains: Optional[str] = None,
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    needle = path_contains.lower() if path_contains else None
    for rec in read_records(path):
        if kind and rec.get("kind") != kind:
            continue
        ts = rec.get("ts", 0)
        if since is not None and ts < since:
            continue
        if until is not None and ts > until:
            continue
        data = rec.get("data", {})
        if event_type and data.get("type") != event_type:
            continue
        if rule and data.get("rule") != rule:
            continue
        if needle:
            hay = f"{data.get('path', '')} {data.get('dest_path', '')}".lower()
            if needle not in hay:
                continue
        out.append(rec)
    return out[-limit:] if limit else out


class EventLog:
    """Writer for the chained log. Refuses to continue a broken chain."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        result = verify_log(self.path)
        if not result.ok:
            raise LogIntegrityError(
                f"The log {self.path} is inconsistent ({result.error}). "
                "Preserve this file as evidence and start a new log in a different state folder."
            )
        self._seq = result.records
        self._head = result.head

    @property
    def head(self) -> str:
        return self._head

    def append(self, kind: str, data: Dict[str, Any], ts: Optional[float] = None) -> Dict[str, Any]:
        if kind not in KINDS:
            raise ValueError(f"invalid kind: {kind!r}")
        with self._lock:
            seq = self._seq + 1
            stamp = time.time() if ts is None else ts
            digest = _record_hash(self._head, seq, stamp, kind, data)
            record = {"seq": seq, "ts": stamp, "kind": kind, "data": data,
                      "prev": self._head, "hash": digest}
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(_canonical(record) + "\n")
                fh.flush()
            self._seq, self._head = seq, digest
            return record
