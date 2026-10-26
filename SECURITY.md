# Security Policy

## Supported versions

Hardening work is tracked on branch `hardening/production-readiness` and releases tagged `v3.14.x`.  
Only versions under active maintenance receive fixes.

## Reporting a vulnerability

Email **trintechdigitaldefense@gmail.com** with:

- Affected version / commit
- Description and impact
- Reproduction steps (defensive proof-of-concept only)

Do **not** open public GitHub issues for security problems. We aim to respond within **72 hours**.

## Security defaults (operator expectations)

- SSH auto-block is **off** until enabled in config
- Firewall changes default to **dry-run**
- Dashboard binds to **loopback** with **view-only** controls unless reconfigured on the host
- Installer does **not** hard-reset the git tree unless `SENTINEL_RECOVER_SYNC=1`

See [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) for the current findings register.
