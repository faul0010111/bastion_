"""Expected Bastion exceptions.

All of them inherit from ``BastionError``: the CLI catches them and prints a
readable message instead of dumping a stack trace on the user.
"""

from __future__ import annotations


class BastionError(Exception):
    """Anticipated error with a message written for the end user."""


class PathValidationError(BastionError):
    """Invalid, missing, unsafe or out-of-scope path."""


class ConfigError(BastionError):
    """Invalid rules file."""


class InventoryError(BastionError):
    """Corrupted or inconsistent inventory."""


class LogIntegrityError(BastionError):
    """The hash chain of the event log does not verify."""


class CryptoError(BastionError):
    """Cryptographic failure (wrong passphrase, tampered file, invalid key)."""


class BackupError(BastionError):
    """Failure while creating, validating or restoring a backup."""


class SigningError(BastionError):
    """Failure creating or verifying signing keys and log checkpoints."""
