# Changelog

## 3.2.0 — 2026-10-24

### Product line (Phases 0–7)
- **Phase 0** — Discovery inventory; improve existing Sentinel (not replace)
- **Phase 5** — Central hardening: agent isolation, fail-closed auth, audit_events, `/v1/audit`
- **Phase 6** — Read-only connectors: contract + normalized schema, `sentinel_local`, Wazuh skeleton
- **Phase 7** — Cases: SQLite cases, status/assign/notes, evidence zip + sha256, per-case audit

### Cases integration
- Auto-open cases from critical engine alerts (`case_hooks`) and connector `--auto-case`
- Dashboard status includes `cases_open` / `cases_open_count` (`dashboard_enrich`)
- Menu / CLI wire via `scripts/apply_cases_wire.py` (runs from `setup.py` / `install.sh`)
- `python3 sentinel.py cases list|create|status|assign|note|evidence`

### Docs
- PHASE0–PHASE7.md, docs/CASES_INTEGRATION.md, ROADMAP updated

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
