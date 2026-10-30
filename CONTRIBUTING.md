# Contributing

Thanks for your interest. Bastion is a **defensive** project, and contributions have to stay that way: no code that attacks, propagates, persists, evades detection, exfiltrates data or encrypts anything the user did not explicitly select. Pull requests that add such capability will be closed, whatever the stated purpose.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a pull request

```bash
ruff check src tests      # lint
mypy                      # strict type checking of src/bastion
python -m pytest --cov    # tests + coverage
```

All three run in CI on every push.

## What a good change looks like

- **Tests with the change.** A new rule needs: it fires, it does *not* fire on the benign shapes, its window expires, its cooldown holds. A new parser needs a test that hostile input raises the project's own error (`BastionError` subclasses), never a bare exception.
- **Honest alerts.** Text says what was *observed*, lists *legitimate causes* and suggests *what to check*. It never claims something is malicious.
- **Safe by default.** Nothing is overwritten without confirmation; paths are validated (`paths.py`); untrusted text (file names!) is escaped wherever it is rendered; secrets never reach logs, command lines or `repr`.
- **Few dependencies.** Runtime dependencies stay at `cryptography` and `watchdog`. Please discuss before adding another.
- **Fictional data only** in tests and examples. Never commit real documents, keys or passphrases.

## Property-based tests

`tests/test_properties.py` uses [hypothesis](https://hypothesis.readthedocs.io). If one fails, it prints a minimal falsifying example; please include it in the issue. Tests must be deterministic given their input (for example, do not depend on `time.time()` inside the property).

## Adding a detection rule

See "Adding a rule" at the end of [`docs/detection-rules.md`](docs/detection-rules.md).

## Reporting security issues

See [`SECURITY.md`](SECURITY.md); do not use public issues for vulnerabilities.
