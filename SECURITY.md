# Security policy

PVault is pre-alpha software. No released revision is currently approved for
real credentials, production use, or as the only copy of important data. The
project has not received an independent security audit.

## Supported versions

Only the current development branch receives security fixes. There is no
backport or response-time commitment before the first stable release.

| Version | Security support |
| --- | --- |
| Development branch | Best effort |
| 0.x pre-alpha builds | No production support |

## Reporting a vulnerability

Do not open a public issue containing an exploit, a malformed vault, a recovery
code, credentials, memory dumps, or other sensitive material.

Use the repository host's private vulnerability-reporting feature when it is
available. If the project is hosted without such a feature, open a public issue
that contains only the words "security contact requested" and a way for a
maintainer to contact you; wait for a private channel before sharing details.

Include, when safe:

- the affected revision or version;
- operating system, architecture, libc, and compiler;
- the observed impact and expected behavior;
- minimal reproduction steps using synthetic secrets only;
- whether disclosure is already public; and
- a suggested embargo date, if relevant.

Maintainers should acknowledge a complete private report, reproduce it with
synthetic data, prepare tests and a fix, and coordinate disclosure. Because the
project is volunteer-run and pre-alpha, no fixed response SLA is promised.

## High-priority findings

Reports are particularly important when they involve:

- unauthenticated decryption or a cryptographic nonce/key reuse;
- master-password, VMK, recovery-key, or record leakage;
- accepting modified, truncated, non-canonical, or unauthenticated vault data;
- parser memory corruption or attacker-controlled allocation;
- secrets appearing in `argv`, the environment, logs, core dumps, temporary
  files, terminal output, or persistent clipboard history;
- unsafe replacement, backup, or restore behavior that can destroy the last
  valid vault; or
- bypass of recovery-key validation or file permissions.

## Handling security artifacts

- Reproduce with newly generated test credentials only.
- Encrypt sensitive reports and artifacts in transit.
- Do not upload a reporter's vault to CI, issue trackers, paste sites, or crash
  reporting services.
- Delete local reproductions securely when they are no longer needed, subject
  to any coordinated disclosure agreement.
- Never request a user's master password or recovery key.

## Security claims

The source being available makes review possible; it does not by itself make
PVault secure. The project does not claim protection from a compromised kernel,
root user, keylogger, malicious display server, hostile clipboard manager, or a
process that can inspect the unlocked application. See `THREAT_MODEL.md` for the
complete boundary.
