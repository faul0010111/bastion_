# Changelog

All notable changes. Format based on [Keep a Changelog](https://keepachangelog.com/); versions follow [SemVer](https://semver.org/).

## [0.2.0]

### Added
- **Signed log checkpoints** (`bastion sign keygen`, `bastion log checkpoint`, `bastion log verify --public-key`): Ed25519 signatures over "N records, head H". Detects rewritten history, truncation and swapped logs even when the hash chain was rebuilt consistently. Private keys are sealed with scrypt + AES-256-GCM (same primitive as data keys, domain-separated) and never overwritten.
- **`bastion status`**: one-screen health check with a non-zero exit code when something needs attention (broken chain, failed checkpoint, recent high-severity alerts, unreadable baseline).
- **`bastion report`**: self-contained HTML (no scripts, no external resources, CSP, everything escaped), Markdown or JSON incident report with timeline, alerts, active folders, evidence anchors and **monitoring coverage gaps**.
- **Three detection rules**: `header_lost` (known file header disappeared, for already-compressed formats where entropy cannot jump), `uniform_extension` (many files renamed to one new extension) and `note_dropped` (identical small file created in many folders).
- Content-type detection from magic bytes (`filetypes.py`); inventories and events now carry `magic` / `prev_magic`.
- `docs/detection-rules.md`: every rule, its false-positive sources and tuning advice.
- Property-based tests (hypothesis), CLI tests for every command, coverage reporting, `ruff` and strict `mypy` in CI.
- `CONTRIBUTING.md`, `SECURITY.md`.

### Changed
- The simulation now exercises all ten rules (PDF-like files losing their header, a harmless notice dropped in several folders, one new extension).
- `crypto.py` exposes the passphrase-sealing primitive (`wrap_secret`, `read_wrapped_secret`, `write_new_private_file`) instead of keeping it private.
- Version bumped to 0.2.0.

### Compatibility
- Inventories written by 0.1 still load; they carry no type information, so `header_lost` stays silent for files in them until the baseline is refreshed (`bastion inventory --update`).
- Existing key files and `.bst` files are unchanged.

## [0.1.0]

First public version: monitoring with a rule engine, verifiable inventory, hash-chained log, canary files, safe simulation, backup with manifest and safe restore, AES-256-GCM encryption of chosen files with documented key management, CLI and automated tests.
