# Detection rules

Bastion has ten rules. Each one counts **distinct** files (or folders) inside a sliding time window and raises an alert when the count reaches its threshold. All of them are signals for analysis: every alert lists legitimate causes to rule out before concluding anything.

How the engine behaves, in general:

- **Deterministic.** The window is driven by the event's own timestamp, not the wall clock, so the same events always give the same alerts (`bastion verify` and the tests rely on this).
- **Distinct counting.** Modifying the same file 100 times counts once.
- **Cooldown.** After a rule fires it stays quiet for `cooldown_seconds` (default 30) to avoid alert floods.
- **Bounded memory.** Windows older than their `window_seconds` are discarded, including the per-extension and per-content groups.
- **Configurable and strict.** Unknown keys or out-of-range values in a rules file are rejected with a clear error. `bastion rules` prints every default as a starting point.

| Rule | Severity | Default | Needs |
|---|---|---|---|
| [`mass_modification`](#mass_modification) | medium | 15 in 10 s | events |
| [`mass_rename`](#mass_rename) | medium | 10 in 10 s | events |
| [`mass_deletion`](#mass_deletion) | medium | 10 in 10 s | events |
| [`extension_change`](#extension_change) | medium | 8 in 15 s | events |
| [`entropy_spike`](#entropy_spike) | high | 8 in 15 s | entropy of the file before and after |
| [`header_lost`](#header_lost) | high | 6 in 15 s | file type of the file before and after |
| [`uniform_extension`](#uniform_extension) | medium | 6 in 15 s | events |
| [`note_dropped`](#note_dropped) | high | 5 folders in 30 s | SHA-256 and size |
| [`canary_touched`](#canary_touched) | high | 1 | canary files deployed |
| [`correlated_signals`](#correlated_signals) | high | 3 rules in 60 s | other rules |

## mass_modification

Many different files were modified in a short time. Duplicate notifications without a content change (same SHA-256) are dropped before counting.

*Legitimate causes:* software updates, reindexing, builds, cloud sync, restoring a backup.
*Tuning:* raise `threshold` or add noisy folders' patterns to `ignore_patterns`. Not meant to be sensitive on its own; its value is in the correlation.

## mass_rename

Many different files were renamed or moved. A "save through a temporary file" (`~$doc`, `.tmp`, `.swp`) is recognized and counted as a *modification*, not a rename.

*Legitimate causes:* reorganizing folders, bulk-rename tools, planned migrations.

## mass_deletion

Many different files were deleted. Moving a file out of the monitored folder is also recorded as a deletion.

*Legitimate causes:* cleaning temporary folders, uninstalling, archive jobs.

## extension_change

Renames that change a file's extension (`report.docx` → `report.docx.locked`, `a.txt` → `a`). Counts any new extension; see `uniform_extension` for the more specific case.

*Legitimate causes:* bulk format conversion, tools that organize files by type.

## entropy_spike

A file's content went from structured to random-looking. The rule needs **both**:

- `entropy >= min_entropy` (default 7.5 bits/byte, over the first 1 MiB), and
- `entropy - prev_entropy >= min_delta` (default 2.5), and
- `size >= min_size_bytes` (default 1024).

The *jump* is what matters. A `.zip` or `.jpg` has high entropy from the day it is created, so a created file, or a file that was already high-entropy, never triggers this rule.

*Legitimate causes:* bulk compression, exporting to compressed formats, encryption you did on purpose.
*Blind spot:* files that were **already** high-entropy before the change. That is exactly what `header_lost` is for.

## header_lost

A modified or renamed file used to start with a known binary header (PDF, ZIP/Office, PNG, JPEG, GIF, legacy Office, gzip, 7z, RAR, SQLite, ELF, Ogg, FLAC, MP3, RIFF, MP4) and now starts with something unrecognizable **and** looks random (`entropy >= min_entropy`, default 7.0; `size >= min_size_bytes`, default 512).

Why it exists: encrypting a `.docx` or `.pdf` barely changes its entropy, so `entropy_spike` stays silent, but the header disappears.

What it deliberately ignores:

- Files that were plain text (they never had a header to lose; `entropy_spike` covers them).
- Files that changed to a *different* known format (a conversion, not a loss).
- Files whose baseline carries no type information (inventories made by Bastion 0.1).
- Low-entropy or tiny results.

*Legitimate causes:* a program that rewrites files in a proprietary or deliberately encrypted format; a broken export.
*Limits:* only the signatures in `src/bastion/filetypes.py`. Adding one is a one-line change plus a test.

## uniform_extension

Many different files were renamed so that they now share **the same** new extension (the alert names it, for example `.locked`). Different new extensions do not add up.

*Legitimate causes:* bulk format conversion; an export or archive tool that tags its output.
*Tuning:* usually kept at its default; it is cheap and specific.

## note_dropped

The **same** small file (identical SHA-256, between `min_size_bytes` 40 and `max_size_bytes` 64 KiB) was created in at least `threshold` different folders. Empty and tiny files are excluded because they are identical by nature (`.gitkeep`, `__init__.py`).

*Legitimate causes:* project scaffolding, unpacking an archive that ships a README or LICENSE in every folder, sync clients.
*What to do:* read one of the files. If you did not create them, do not follow any instruction they contain, and keep them as evidence.

## canary_touched

Any modification, rename or deletion of a canary file (`bastion canary create`). Nobody has a reason to open these files, so the rule has a threshold of 1. A *creation* is ignored (it is Bastion itself placing the file). `bastion verify` also compares canaries against their recorded SHA-256, so a canary touched while the monitor was off is still reported.

*Legitimate causes:* an indexer, antivirus scan or backup tool opening and saving the file; a curious person.

## correlated_signals

Several *different* rules fired inside the window (default: 3 rules in 60 s). It raises the **priority** of the analysis, never the certainty of a cause. Large legitimate operations (a migration, a restore) can trigger several rules at once.

## Choosing thresholds for your environment

1. Run `bastion monitor --verbose` for a normal week and note which rules fire.
2. Raise the threshold of any rule that fires on routine work, or `ignore_patterns` for the noisy folder (build output, cache, sync temp files).
3. Keep `canary_touched`, `entropy_spike` and `header_lost` strict; they are the most specific.
4. Re-run `bastion simulate --base ...` with your rules file in mind to confirm the burst still triggers everything.

## Adding a rule

1. Add the name to `RULE_NAMES` and defaults to `_default_rules()` in `config.py` (with a `RuleSettings` subclass if it needs extra fields; the parser picks the allowed keys from the dataclass).
2. Add its text to `_META` and either a matcher (`_MATCHERS`, one window per rule) or a grouper (`_GROUPERS`, one window per group such as an extension or a content hash) in `rules.py`.
3. Add tests: it fires, it does **not** fire on the benign shapes you listed above, the window expires, the cooldown holds.
4. Document it here, including its false-positive sources.
