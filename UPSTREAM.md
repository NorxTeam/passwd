# Norx passwd upstream boundary

This repository is the maintained fork `NorxTeam/passwd` of
`shadow-maint/shadow`. The upstream baseline is `master`; the Norx work is
isolated under `norx/` and is reviewed against that upstream branch.

The upstream `src/passwd.c` remains the provenance reference for password
administration semantics. Norx does not reuse its host `/etc/passwd`, PAM,
`crypt(3)`, or unbounded command-line interface. `norx/` calls the bounded
`userdb` API for change, reset, lock, unlock, policy validation, hashing, and
atomic persistence.

Passwords and encoded hashes are accepted only as in-memory API inputs. They
are never put in argv, the environment, audit records, error text, or serial
output. The target smoke uses deterministic verifier/hasher adapters only; a
production image must inject a reviewed Argon2id implementation with secure
random salts and secret clearing.
