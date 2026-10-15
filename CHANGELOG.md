# Changelog

## 3.1.0 — 2026-10-15

### Trust
- LICENSE (authorized defensive use) + copyright headers on source files
- README updated for public repo; single install path; legacy `install-sentinel.sh` removed
- VERIFY.md + SHA256SUMS for install artifacts
- pytest expanded (40+); CI fails on test failure

### MSP / product
- Per-agent API keys on central (issue / verify / revoke); enroll prefers HTTPS
- Encrypted backup / restore (`backup`, `restore`)
- Opt-in canary SMB share (`smb-canary`)
- Dashboard RBAC helpers (admin vs viewer)
- Dockerfile, docker-compose.yml, UNRAID.md

## 3.0.0 — 2026-10-15

- Plain source tree (no base64 assembly)
- Config schema, structured logging, multi-channel alerting, severity, containment, threat intel
- Central server, Windows agent, scheduled reports, self-defense, watchdog
