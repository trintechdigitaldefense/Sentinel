# Changelog

## 3.0.0 — 2026-10-15

### Breaking / architecture
- Removed base64 `engine_chunks`, `assemble_engine.py`, and all `wire_*` / `fix_*` / `restore_*` scripts.
- `sentinel.py` is plain, reviewable source. `setup.py` is dependency-check + config init only.

### Added
- Config schema validation (`modules/config_schema.py`) with wizard helpers
- Structured JSON logging with daily rotation (`modules/logging_setup.py`)
- Multi-channel alerting: WhatsApp, SMTP, webhook, syslog + deduplication
- Severity scoring model (INFO→CRITICAL)
- Opt-in containment actions (kill process, block IP, disable user) — default OFF
- Threat intel enrichment (AbuseIPDB, OTX) with 24h cache
- Central management server (`sentinel_central`) for MSP multi-client mode
- Full Windows agent (`agents/sentinel_win_agent.py`) + `install.bat`
- Scheduled reporting helper (`modules/scheduled_report.py`)
- Self-defense core hash verification (`modules/self_defense.py`)
- Watchdog / heartbeat (`modules/watchdog.py`)
- pytest suite + GitHub Actions CI
- One-line `install.sh`

### Security
- Authorized defensive use only. No offensive capabilities.
