# Security Policy

## Supported versions

Published tagged releases are the support reference; the previously documented `v3.14.x` line remains the last explicitly identified release series. The repository installer currently reports source version `3.16.21`, but that value is development metadata and does not by itself mean a corresponding release has been published or security-certified.

The current security remediation work is tracked separately on branch `remediation/production-security-hardening`. Do not treat that branch as a supported release until its pull request is reviewed, merged, tagged, and its release gates are completed.

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
