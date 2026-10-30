# Security policy

Bastion is an educational, defensive project. It has no network code and does not run with elevated privileges, but it handles keys, file names and evidence, so security reports are welcome.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Use GitHub's *private vulnerability reporting* ("Security" tab → "Report a vulnerability") on this repository. Include the version (`bastion --version`), what you expected, what happened and, if possible, a minimal reproduction using fictional files.

You can expect an acknowledgement within a few days. This is a volunteer project, so there is no formal SLA.

## In scope

- Path traversal or symlink escapes in backup, restore, simulation or reports.
- Ways to make Bastion overwrite, delete or encrypt files it should not touch.
- Flaws in key handling: keys or passphrases reaching logs, command lines or world-readable files; weak parameters accepted from a key file.
- Ways to forge a signed checkpoint, or make verification pass on a log that was rewritten before the checkpoint.
- Markup or script injection through file names or alert text into the HTML report.
- Crashes or unbounded resource use triggered by crafted input (rules file, manifest, log, checkpoint, key file).

## Out of scope

- An attacker who already has administrator/root rights on the monitored machine (they can stop the monitor or rewrite everything; the signed checkpoints and off-machine copies exist for that case).
- Detection quality (a ransomware sample that evades the heuristics): please open a normal issue, with the behavior you saw.
- Vulnerabilities in dependencies; report those upstream (`cryptography`, `watchdog`).

## Design decisions worth knowing before you report

- Passphrases are never accepted on the command line; `BASTION_PASSPHRASE` exists for demos and automation and prints a warning.
- Key files are created with `0600` and `O_EXCL`; Bastion never overwrites a key.
- Reports contain file names from the monitored folder and should be treated as sensitive.
- A signed checkpoint says nothing about records written after it.
