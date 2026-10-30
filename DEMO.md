# Demo script (5 to 7 minutes)

For interviews or the GitHub page. Everything runs locally, with fictional data.

## Setup (before you start)

```bash
pip install -e ".[dev]"
export BASTION_HOME=$(mktemp -d)        # isolated demo state
```

## 1. The problem (30 s)

> "Small businesses usually discover ransomware only after the damage is done, and their backup is often stale, also hit, or never tested. Bastion gives **visibility**, **trustworthy evidence** and **verifiable recovery**, in a purely defensive way with no offensive capability."

## 2. Safe simulation, the "wow" moment (1.5 min)

```bash
bastion simulate --pause 2
```

Points to highlight while it runs:
- **Phase 1** (normal edits) raises no alert: the system does not cry wolf.
- In **phase 2**, **explained** alerts appear: what was seen, possible legitimate causes, what to do, and the reminder that it is a "signal for analysis".
- `entropy_spike`: "the file went from text (≈4 bits/byte) to ≈8: it looks like random content". The heuristic looks at the **jump**, not the absolute value, so `.zip` and `.jpg` files do not cause false positives.
- `header_lost`: eight PDF-like files lose their `%PDF-` header. Their entropy was already ~8, so an entropy rule would never see it; this is why the rule exists.
- `uniform_extension` and `note_dropped`: fifteen files now share one new extension; the same harmless notice appears in six folders.
- `correlated_signals`: several independent signals together raise the priority.
- At the end: "Log chain: intact" and the temporary folder is gone. The simulation only touches files it created itself.

## 3. Tamper-evident evidence (1 min)

```bash
bastion simulate --keep                 # keeps the folder; copy the printed path
bastion log verify --state .bastion_sim/run-XXXX/state
# edit any line of events.jsonl with an editor...
bastion log verify --state .bastion_sim/run-XXXX/state    # → CHAIN BROKEN at record N
```

> "Every record carries the hash of the previous one. Whoever deletes or edits the history leaves a trace. And if an attacker rebuilds the whole chain, the anchor you wrote down off the machine exposes it."

## 3b. Evidence an attacker cannot quietly rewrite (1.5 min)

```bash
bastion sign keygen --private /tmp/keys/sign.json --public /tmp/keys/sign.pub
bastion log checkpoint --state .bastion_sim/run-XXXX/state --signing-key /tmp/keys/sign.json --output /tmp/cp.json
```

Now play the attacker: edit one record **and recompute every hash after it** (the snippet in `tests/test_signing.py::rebuild_chain` does exactly that), then:

```bash
bastion log verify --state .bastion_sim/run-XXXX/state                 # chain alone: "Chain intact" (fooled)
bastion log verify --state .bastion_sim/run-XXXX/state --public-key /tmp/keys/sign.pub --checkpoint /tmp/cp.json
# → FAILED: Record N no longer matches the signed hash: history before this checkpoint was rewritten.
```

> "A hash chain proves nobody edited the middle, not that nobody rebuilt the whole thing. The signed checkpoint lives *off* the machine and is signed with a key the attacker never had, so rebuilding the chain does not help them."

## 3c. Health check and incident report (1 min)

```bash
bastion status --state .bastion_sim/run-XXXX/state                     # exit code 1: recent high-severity alerts
bastion report --state .bastion_sim/run-XXXX/state --public-key /tmp/keys/sign.pub --output /tmp/report.html
```

Open `/tmp/report.html`: timeline, every alert with legitimate causes and a suggested check, evidence anchors, and **monitoring coverage gaps**.

> "It is one self-contained file: no scripts, no external requests, and every file name is escaped, because file names are attacker-controlled input."

## 4. A backup that actually proves itself (1.5 min)

```bash
bastion backup create examples/sample_data /tmp/vault --name demo     # note the digest
bastion backup validate /tmp/vault/demo --digest <digest>
echo "junk" >> /tmp/vault/demo/files/clients.csv
bastion backup validate /tmp/vault/demo                               # → NOT intact
bastion backup restore /tmp/vault/demo --to /tmp/test                 # → refuses: backup failed validation
```

> "Restoring only works from a verified backup, never overwrites without explicit confirmation, and the 'same drive' warning reinforces the 3-2-1 rule with an offline copy."

## 5. Encryption without inventing anything (1 min)

```bash
bastion crypto keygen --key /tmp/keys/bastion.json
bastion crypto protect examples/sample_data/sales_report.md --key /tmp/keys/bastion.json
bastion crypto protect /tmp                       # → refuses: folders are not accepted
```

> "AES-256-GCM from the `cryptography` library, key protected by scrypt, per-file subkey via HKDF. The key never sits next to the data, never reaches a log, and the tool **refuses** to become an indiscriminate encryptor: no folders, at most 20 files, originals preserved."

## 6. Wrap-up (30 s)

- Show `python -m pytest --cov`: 235 tests at 91% coverage, including property-based tests ("any byte flipped in the log or an encrypted file is detected"), plus `ruff` and strict `mypy`.
- Show the **Threat model** and **Known limitations** sections of the README: "I know what the tool solves and what it does not."

### Questions that tend to come up

- **"Isn't this an antivirus?"** No. It is visibility and recovery; it complements antivirus/EDR.
- **"What about false positives?"** Alerts explain legitimate causes; rules are configurable; there is a cooldown and correlation.
- **"Why is the state kept outside the folder?"** So encrypting the folder does not also destroy the evidence.
- **"What if the attacker is an administrator?"** Out of scope; that is why the external anchors, signed checkpoints and offline backups exist.
- **"What if they rebuild the hash chain?"** That is what the signed checkpoint is for (section 3b); records written *after* the newest checkpoint are the residual risk, so create them regularly.
- **"Why not just use entropy?"** Compressed formats are born high-entropy; the jump rule misses them and `header_lost` covers them. Both are documented with their false-positive sources in `docs/detection-rules.md`.
