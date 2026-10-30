"""Detection rule configuration and location of Bastion's state."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from .errors import ConfigError

RULE_NAMES = (
    "mass_modification",
    "mass_rename",
    "mass_deletion",
    "extension_change",
    "entropy_spike",
    "header_lost",
    "uniform_extension",
    "note_dropped",
    "canary_touched",
    "correlated_signals",
)

DEFAULT_IGNORE = (
    "*.swp", "*.swx", "*.tmp", "*~", ".DS_Store", "Thumbs.db", "~$*", ".~lock.*#",
)

MAX_CONFIG_BYTES = 1024 * 1024


@dataclass(frozen=True)
class RuleSettings:
    enabled: bool = True
    threshold: int = 10
    window_seconds: float = 10.0


@dataclass(frozen=True)
class EntropySettings(RuleSettings):
    min_entropy: float = 7.5
    min_delta: float = 2.5
    min_size_bytes: int = 1024


@dataclass(frozen=True)
class HeaderSettings(RuleSettings):
    """``header_lost``: a file with a known header (PDF, ZIP/Office, JPEG...) lost it."""

    min_entropy: float = 7.0
    min_size_bytes: int = 512


@dataclass(frozen=True)
class NoteSettings(RuleSettings):
    """``note_dropped``: identical small files created in many different folders."""

    min_size_bytes: int = 40
    max_size_bytes: int = 65536


def _default_rules() -> Dict[str, RuleSettings]:
    return {
        "mass_modification": RuleSettings(enabled=True, threshold=15, window_seconds=10.0),
        "mass_rename": RuleSettings(enabled=True, threshold=10, window_seconds=10.0),
        "mass_deletion": RuleSettings(enabled=True, threshold=10, window_seconds=10.0),
        "extension_change": RuleSettings(enabled=True, threshold=8, window_seconds=15.0),
        "entropy_spike": EntropySettings(enabled=True, threshold=8, window_seconds=15.0),
        "header_lost": HeaderSettings(enabled=True, threshold=6, window_seconds=15.0),
        "uniform_extension": RuleSettings(enabled=True, threshold=6, window_seconds=15.0),
        "note_dropped": NoteSettings(enabled=True, threshold=5, window_seconds=30.0),
        "canary_touched": RuleSettings(enabled=True, threshold=1, window_seconds=1.0),
        "correlated_signals": RuleSettings(enabled=True, threshold=3, window_seconds=60.0),
    }


@dataclass(frozen=True)
class RulesConfig:
    rules: Mapping[str, RuleSettings]
    cooldown_seconds: float = 30.0
    ignore_patterns: Tuple[str, ...] = DEFAULT_IGNORE

    @classmethod
    def default(cls) -> "RulesConfig":
        return cls(rules=_default_rules())

    @classmethod
    def from_dict(cls, data: Any) -> "RulesConfig":
        if not isinstance(data, dict):
            raise ConfigError("The rules file must contain a JSON object.")
        _check_keys(data, {"cooldown_seconds", "ignore_patterns", "rules"}, "root")
        rules = _default_rules()
        raw_rules = data.get("rules", {})
        if not isinstance(raw_rules, dict):
            raise ConfigError("'rules' must be an object.")
        _check_keys(raw_rules, set(RULE_NAMES), "rules")
        for name, raw in raw_rules.items():
            rules[name] = _parse_rule(name, raw, rules[name])
        cooldown = _num(data.get("cooldown_seconds", 30.0), "cooldown_seconds", 0, 86400)
        patterns = data.get("ignore_patterns", list(DEFAULT_IGNORE))
        if not isinstance(patterns, list) or not all(isinstance(p, str) and p for p in patterns):
            raise ConfigError("'ignore_patterns' must be a list of non-empty strings.")
        return cls(rules=rules, cooldown_seconds=float(cooldown), ignore_patterns=tuple(patterns))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cooldown_seconds": self.cooldown_seconds,
            "ignore_patterns": list(self.ignore_patterns),
            "rules": {name: dataclasses.asdict(s) for name, s in self.rules.items()},
        }


def _check_keys(obj: Mapping[str, Any], allowed: set, where: str) -> None:
    unknown = sorted(set(obj) - allowed)
    if unknown:
        raise ConfigError(
            f"Unknown key(s) in '{where}': {', '.join(unknown)}. "
            f"Allowed: {', '.join(sorted(allowed))}."
        )


def _num(value: Any, where: str, minimum: float, maximum: float, integer: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"'{where}' must be a number.")
    if integer and int(value) != value:
        raise ConfigError(f"'{where}' must be an integer.")
    if not (minimum <= value <= maximum):
        raise ConfigError(f"'{where}' must be between {minimum:g} and {maximum:g} (got {value}).")
    return int(value) if integer else float(value)


def _parse_rule(name: str, raw: Any, base: RuleSettings) -> RuleSettings:
    if not isinstance(raw, dict):
        raise ConfigError(f"Rule '{name}' must be an object.")
    allowed = {f.name for f in dataclasses.fields(base)}
    _check_keys(raw, allowed, f"rules.{name}")
    values = dataclasses.asdict(base)
    for key, value in raw.items():
        where = f"rules.{name}.{key}"
        if key == "enabled":
            if not isinstance(value, bool):
                raise ConfigError(f"'{where}' must be true or false.")
            values[key] = value
        elif key == "threshold":
            values[key] = _num(value, where, 1, 1_000_000, integer=True)
        elif key == "window_seconds":
            values[key] = _num(value, where, 0.1, 3600)
        elif key in ("min_entropy", "min_delta"):
            values[key] = _num(value, where, 0, 8)
        elif key in ("min_size_bytes", "max_size_bytes"):
            values[key] = _num(value, where, 0, 1 << 30, integer=True)
    return type(base)(**values)


def load_config(path: Optional[Path]) -> RulesConfig:
    """Load rules from a JSON file, or return the defaults when ``path`` is None."""
    if path is None:
        return RulesConfig.default()
    path = Path(path).expanduser()
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise ConfigError("Rules file too large (1 MiB limit).")
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ConfigError(f"Rules file not found: {path}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"Could not read '{path}': {exc}") from None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in '{path}': {exc}") from None
    return RulesConfig.from_dict(data)


@dataclass(frozen=True)
class StatePaths:
    """Where Bastion keeps inventory, log, canaries and checkpoints (outside the monitored folder)."""

    base: Path

    @property
    def inventory(self) -> Path:
        return self.base / "inventory.json"

    @property
    def log(self) -> Path:
        return self.base / "events.jsonl"

    @property
    def canaries(self) -> Path:
        return self.base / "canaries.json"

    @property
    def checkpoints(self) -> Path:
        return self.base / "checkpoints.jsonl"

    @property
    def reports(self) -> Path:
        return self.base / "reports"

    def ensure(self) -> None:
        self.base.mkdir(parents=True, exist_ok=True)


def bastion_home() -> Path:
    override = os.environ.get("BASTION_HOME")
    return Path(override).expanduser() if override else Path.home() / ".bastion"


def default_state_dir(root: Path) -> Path:
    tag = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:8]
    return bastion_home() / "state" / f"{root.name or 'root'}-{tag}"


def default_key_path() -> Path:
    return bastion_home() / "key.json"


def default_signing_key_paths() -> Tuple[Path, Path]:
    """(private, public) default locations. Best practice: move the private key off this machine."""
    return bastion_home() / "signing-key.json", bastion_home() / "signing-key.pub.json"
