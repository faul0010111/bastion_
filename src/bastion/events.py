"""Data models: file events and alerts."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

EVENT_TYPES = ("created", "modified", "moved", "deleted")

DISCLAIMER = (
    "This is a signal for analysis: it may have a legitimate cause and, on its own, "
    "does not prove malicious activity."
)


def iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class Event:
    """A change observed on a file (paths are relative to the monitored folder)."""

    type: str
    path: str
    ts: float = field(default_factory=time.time)
    dest_path: Optional[str] = None
    sha256: Optional[str] = None
    size: Optional[int] = None
    entropy: Optional[float] = None
    prev_entropy: Optional[float] = None
    magic: Optional[str] = None
    prev_magic: Optional[str] = None
    note: Optional[str] = None
    source: str = "monitor"

    def __post_init__(self) -> None:
        if self.type not in EVENT_TYPES:
            raise ValueError(f"Invalid event type: {self.type!r}")

    @property
    def affected_path(self) -> str:
        return self.dest_path or self.path

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "time": iso_utc(self.ts),
            "ts": self.ts,
            "type": self.type,
            "path": self.path,
        }
        for key in ("dest_path", "sha256", "size", "entropy", "prev_entropy",
                    "magic", "prev_magic", "note"):
            value = getattr(self, key)
            if value is not None:
                data[key] = value
        data["source"] = self.source
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Event":
        return cls(
            type=data["type"],
            path=data["path"],
            ts=float(data["ts"]),
            dest_path=data.get("dest_path"),
            sha256=data.get("sha256"),
            size=data.get("size"),
            entropy=data.get("entropy"),
            prev_entropy=data.get("prev_entropy"),
            magic=data.get("magic"),
            prev_magic=data.get("prev_magic"),
            note=data.get("note"),
            source=data.get("source", "monitor"),
        )


@dataclass
class Alert:
    """Signal raised by a rule. Always phrased as something to analyze."""

    rule: str
    severity: str  # "high" | "medium" | "low"
    title: str
    explanation: str
    benign_causes: str
    suggestion: str
    ts: float
    threshold: int
    observed: int
    window_seconds: float
    events: List[Dict[str, Any]] = field(default_factory=list)
    total_related: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "time": iso_utc(self.ts),
            "ts": self.ts,
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "explanation": self.explanation,
            "benign_causes": self.benign_causes,
            "suggestion": self.suggestion,
            "threshold": self.threshold,
            "observed": self.observed,
            "window_seconds": self.window_seconds,
            "total_related": self.total_related,
            "events": self.events,
            "disclaimer": DISCLAIMER,
        }
