"""Safe simulation: demonstrates the alerts without touching real data.

Safety guarantees:
* everything happens inside ``<base>/run-XXXX/``, created by this function;
* the ``Sandbox`` only operates on files it created itself and checks, on every
  operation, that the resolved path is still inside the simulation folder;
* there is no encryption and no external code: the "burst" merely overwrites
  FICTIONAL files with random bytes (``os.urandom``) to reproduce the entropy
  signature Bastion looks for, and renames/deletes fictional copies;
* at the end the simulation folder is removed (unless ``keep=True``).
"""

from __future__ import annotations

import os
import random
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Set

from .canary import deploy_canaries
from .config import RulesConfig, StatePaths
from .errors import BastionError
from .eventlog import LogVerification, verify_log
from .events import Alert
from .monitor import Monitor
from .paths import is_within

_WORDS = ["report", "invoice", "customer", "order", "contract", "proposal", "budget", "delivery", "stock", "meeting", "project", "deadline", "payment", "receipt", "supplier", "team", "result", "analysis", "target", "sale", "purchase", "product", "service"]

N_FILES = 60
N_MODIFY, N_RENAME, N_DELETE = 30, 15, 12
N_PDFS = 8          # fictional PDF-like files (header + random body) for the header_lost rule
N_FOLDERS = 6       # fictional department folders for the note_dropped rule
CANARY_NAME = "000-confidential-finance.txt"
NOTE_NAME = "SIMULATION-NOTICE.txt"
NOTE_TEXT = (b"This harmless file was created by the Bastion simulation to demonstrate the "
             b"'note_dropped' rule. It contains no instructions and nothing to act on.\n")


class Sandbox:
    """File operations restricted to the simulation folder and to files it created."""

    def __init__(self, data_dir: Path) -> None:
        self.root = data_dir.resolve()
        self._owned: Set[Path] = set()

    def _guard(self, path: Path) -> Path:
        resolved = path.resolve()
        if not is_within(resolved, self.root) or resolved == self.root:
            raise BastionError(f"Operation refused outside the simulation area: {path}")
        return resolved

    def mkdir(self, name: str) -> Path:
        target = self._guard(self.root / name)
        target.mkdir(exist_ok=True)
        return target

    def create(self, name: str, data: bytes) -> Path:
        target = self._guard(self.root / name)
        target.write_bytes(data)
        self._owned.add(target)
        return target

    def _owned_path(self, name: str) -> Path:
        target = self._guard(self.root / name)
        if target not in self._owned:
            raise BastionError(f"Refused: '{name}' was not created by the simulation.")
        return target

    def overwrite_with_noise(self, name: str) -> None:
        target = self._owned_path(name)
        target.write_bytes(os.urandom(4096))

    def append_text(self, name: str, text: str) -> None:
        target = self._owned_path(name)
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(text)

    def rename(self, name: str, new_name: str) -> None:
        src = self._owned_path(name)
        dst = self._guard(self.root / new_name)
        os.replace(src, dst)
        self._owned.discard(src)
        self._owned.add(dst)

    def delete(self, name: str) -> None:
        target = self._owned_path(name)
        target.unlink()
        self._owned.discard(target)

    def adopt(self, name: str) -> None:
        """Mark as "owned by the simulation" a file it created through another path."""
        self._owned.add(self._guard(self.root / name))


def _fake_text(rng: random.Random, size: int = 4096) -> bytes:
    parts: List[str] = []
    while sum(len(p) + 1 for p in parts) < size:
        parts.append(rng.choice(_WORDS))
    return (" ".join(parts) + "\n").encode("utf-8")


@dataclass
class SimulationReport:
    run_dir: Path
    alerts: List[Alert] = field(default_factory=list)
    log_check: Optional[LogVerification] = None
    kept: bool = False
    removed: bool = False

    @property
    def rules_triggered(self) -> Set[str]:
        return {a.rule for a in self.alerts}


def run_simulation(
    base_dir: Path,
    *,
    keep: bool = False,
    seed: int = 1234,
    pause: float = 0.0,
    say: Callable[[str], None] = lambda _msg: None,
    on_alert: Optional[Callable[[Alert], None]] = None,
) -> SimulationReport:
    base_dir = Path(base_dir).resolve()
    base_dir.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=base_dir)).resolve()
    data_dir, state_dir = run_dir / "data", run_dir / "state"
    data_dir.mkdir()
    report = SimulationReport(run_dir=run_dir)
    rng = random.Random(seed)  # noqa: S311 - fictional demo content only, nothing cryptographic
    box = Sandbox(data_dir)
    state = StatePaths(state_dir)
    names = [f"doc_{i:03d}.txt" for i in range(N_FILES)]
    pdfs = [f"scan_{i:02d}.pdf" for i in range(N_PDFS)]
    folders = [f"dept_{i:02d}" for i in range(N_FOLDERS)]

    try:
        say(f"Simulation folder (fictional files): {data_dir}")
        for n in names:
            box.create(n, _fake_text(rng))
        for n in pdfs:   # PDFs are already high-entropy: only the lost header gives them away
            box.create(n, b"%PDF-1.4\n" + rng.randbytes(2048))
        for folder in folders:
            box.mkdir(folder)
            box.create(f"{folder}/summary.txt", _fake_text(rng, 600))
        state.ensure()
        for decoy in deploy_canaries(data_dir, state.canaries):
            box.adopt(decoy)
        say(f"{N_FILES + N_PDFS + N_FOLDERS} fictional files + canaries created. Starting the monitor...")

        monitor = Monitor(data_dir, state, RulesConfig.default(), on_alert=on_alert)
        monitor.start()
        try:
            time.sleep(0.5)  # let the observer settle

            say("\nPhase 1: normal activity (3 small edits). Should not raise alerts.")
            for n in names[-3:]:
                box.append_text(n, "\nreviewed.")
                time.sleep(0.2)
            monitor.wait_idle(0.6)
            time.sleep(pause)

            say(f"\nPhase 2: FICTIONAL burst on simulation files "
                f"({N_MODIFY} overwritten with random bytes, {N_PDFS} PDFs losing their header, "
                f"{N_RENAME} renamed, {N_DELETE} deleted, a notice dropped in {N_FOLDERS} folders, "
                f"1 canary touched).")
            for n in names[:N_MODIFY]:
                box.overwrite_with_noise(n)
            for n in pdfs:
                box.overwrite_with_noise(n)
            for folder in folders:
                box.create(f"{folder}/{NOTE_NAME}", NOTE_TEXT)
            for n in names[N_MODIFY:N_MODIFY + N_RENAME]:
                box.rename(n, n + ".simulated")
            for n in names[N_MODIFY + N_RENAME:N_MODIFY + N_RENAME + N_DELETE]:
                box.delete(n)
            box.append_text(CANARY_NAME, "\n(simulation: canary touched)")
            monitor.wait_idle(1.5, timeout=20)
        finally:
            monitor.stop()
        report.alerts = list(monitor.alerts)
        report.log_check = verify_log(state.log)
    finally:
        if keep:
            report.kept = True
        else:
            _cleanup(run_dir, base_dir)
            report.removed = not run_dir.exists()
    return report


def _cleanup(run_dir: Path, base_dir: Path) -> None:
    """Remove ONLY the run-* folder created by this simulation, inside ``base_dir``."""
    if run_dir.parent != base_dir or not run_dir.name.startswith("run-") or run_dir.is_symlink():
        raise BastionError(f"Cleanup refused for safety: {run_dir}")
    shutil.rmtree(run_dir)
