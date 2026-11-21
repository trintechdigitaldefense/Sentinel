# Security Policy

## Supported versions

Sentinel is actively maintained on the repository's `main` branch. The project is currently classified as a **pilot candidate**, not a certified production release. Check the current commit and [release checklist](docs/RELEASE_CHECKLIST.md) before deploying; do not assume older version tags receive security fixes.

## Reporting a vulnerability

Email **trintechdigitaldefense@gmail.com** with:

- Affected version / commit
- Description and impact
- Reproduction steps (defensive proof-of-concept only)

Do **not** open public GitHub issues for security problems. We aim to respond within **72 hours**.

## Security defaults and operator expectations

- SSH auto-block is **off** until explicitly enabled in configuration.
- Firewall changes default to **dry-run**; live changes require deliberate operator confirmation.
- Dashboard backend binds to **127.0.0.1**; remote access requires a separately configured and verified TLS reverse proxy.
- Dashboard controls remain subject to configured role and `allow_control` authorization.
- Runtime configuration and installer writes use guarded/atomic handling in the hardened paths; preserve backups and inspect failures rather than forcing recovery.
- Installer recovery that can discard local work requires explicit `SENTINEL_RECOVER_SYNC=1`; never use it as a routine upgrade step.

See [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) for current release gates and [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) for the historical audit snapshot and its limitations.
