# Changelog

## [3.13.4] — 2026-10-25

### Real-time threat level color coding
- CLI monitor: CLEAR green · WATCH cyan · ELEVATED yellow · HIGH red · CRITICAL magenta
- Severity lines colorized; dashboard badges/rows match (elev/info/bad)


## [3.13.3] — 2026-10-25

### CLI monitor interval options
- `monitor --interval N` / `-i N` (min 3s)
- Presets: `fast` (5), `normal` (10), `slow` (30), `hunt` (60), `idle` (120)
- `--once`, `--json`, `--quiet`, `--emit`, `--help`


## [3.13.2] — 2026-10-25

### Real-time monitoring + restored controls toggle
- Dashboard **live poll** of `/api/realtime?scan=1` (8–12s) without full page reload
- Restored **controls switch** (on/off) with reliable token API
- CLI continuous monitor: `python3 sentinel.py monitor` (or `realtime-monitor`)


## [3.13.1] — 2026-10-25

### Real-time threats + dashboard control toggle
- modules/realtime_threat.py — RS cmdline, behavioral, risky ports, criticals
- Dashboard panel + /api/realtime; faster refresh on HIGH/CRITICAL
- Control Enable/Disable toggle (POST /api/control-mode)
- CLI: python3 sentinel.py realtime


## [3.13.0] — 2026-10-25

### Full dashboard surface
- Wired: hunt, critical, alerts, visibility, SIEM, firewall, SSH blocks, blocklist, cases, go-live, service, quiet
- Control actions: doctor, ops, quiet on/off, field-soak, visibility, service-status, critical ACK
- APIs: `/api/status`, `/api/critical`, `/api/go-live`, `/api/ops`, `/api/visibility`, `POST /api/action`

## [3.12.1] — 2026-10-25

### Dashboard
- Critical alert **ACK / ACK all** from the UI (control mode)
- **Go-live status** panel from last `go-live` report
- API: `GET /api/critical`, `GET /api/go-live`, `POST /api/critical/ack`, `POST /api/critical/ack-all`
- View-only mode respects `dashboard.allow_control: false`

## [3.12.0] — 2026-10-25

### Host operational setup
- `python3 sentinel.py go-live` — one-shot baselines (FIM/SUID/persistence), canaries, alert ship channel, heartbeat
- `--service` optionally installs always-on hunt
- docs/GO_LIVE.md; menu item 21

## [3.11.1] — 2026-10-25

### Fixes
- field-soak: call `threat_sim.run([...])` with a scenario **list** (was iterating string chars)
- phase2: self-contained module (no missing phase2_a/b ImportError)
- dashboard version aligned to 3.11.1

## [3.11.0] — 2026-10-25

### Pilot readiness freeze
- `field-soak` command + docs/FIELD_SOAK.md (canary, sim, WhatsApp/Splunk channel check)
- docs/SALES_PACK.md — one-page runbook + fixed pilot pricing guide
- README version badge stabilized to 3.11.0; menu notes field soak
- Explicit product focus: no feature sprawl until pilots complete

## [3.10.2] — 2026-10-25

### Splunk HEC integration
- Full HEC configure/health/batch/flush helpers in `modules/siem.py`
- CLI: `siem splunk-configure`, `siem splunk env|health|flush`
- Env: `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN`, `SPLUNK_HEC_INDEX`
- docs/SPLUNK.md

## [3.10.0] — 2026-10-25

### SIEM / centralized logging
- `modules/siem.py` — syslog (UDP/TCP), CEF, Splunk HEC, webhook, JSONL ship file
- Wired into AlertRouter + send_alert when `alerting.siem.enabled`
- CLI: `siem status|test|cef-sample`
- docs/SIEM.md

## [3.9.1] — 2026-10-25

### Persistent critical alerts
- `modules/critical_alerts.py` — open critical events stored until operator ACK
- Quiet hours / hygiene **cannot suppress** critical types
- Hunt cycle re-surfaces unacked criticals every loop
- CLI: `critical status|ack <id>|ack-all|resurface`
- Ops status shows open critical count

## [3.9.0] — 2026-10-25

### Hunt loop, alerts, ops
- `modules/hunt_cycle.py` — structured cycle: heartbeat → FIM/process/SSH/outbound/users/cron → persistence → visibility → sensors → maintenance
- Per-check isolation + `hunt_metrics.json` (timing, errors, alert types)
- `send_alert` routes through AlertRouter (dedup, channels, offline queue) with severity map
- `modules/ops_status.py` + CLI `ops` — hunt health, alerts, service, blocks, visibility
- Menu 12 = Ops status

## [3.8.0] — 2026-10-25

### Visibility (devices / processes / FIM / persistence)
- `modules/visibility.py` — unified inventory: ARP devices, process snapshot, FIM, SUID, persistence
- Network scan falls back to ARP when nmap missing/timeout
- Hunt loop refreshes device + process inventory each cycle
- CLI: `visibility` · `visibility devices` · `visibility processes`
- Detection menu: Full visibility inventory

## [3.6.1] — 2026-10-25

### Menu + CLI wiring
- Interactive menu expanded: Detection, Firewall, Ops submenus; Pilot + Doctor on main
- Wired `firewall` / `fw` and `cases` CLI into sentinel.py (were missing)
- Help text lists firewall, cases, pilot, sim

## [3.5.2] — 2026-10-25

### Pilot validation workflow
- Full phased pilot: preflight → baselines → deception → detection → service
- Go/No-Go checklist + `~/.sentinel/data/pilot_report.json`
- `sentinel pilot --fix` creates missing persistence/SUID baselines
- docs/PILOT.md on-site runbook

## [3.5.0] — 2026-10-25

### Product hygiene
- README rewrite: feature matrix, menu preview, full CLI table, architecture
- docs/THREAT_MODEL.md — SMB-focused control mapping
- CI: ruff critical checks, module compile, firewall smoke, pytest
- tests/test_persistence_behavioral.py — persistence, SUID, behavioral, lockout

## [3.4.0] — 2026-10-25

### Persistence expansion + behavioral shells + self-FIM
- **persistence_hunt**: systemd timers/sockets, authorized_keys drift, LD_PRELOAD create/change, profile.d, rc files
- **behavioral_shell**: deleted `/proc/pid/exe`, TTY+TCP established, web-server→shell parent anomaly
- **Self-FIM**: tracks core modules + setup.py; full-tree git updates refresh baseline; partial module change alerts
- CLI: `sentinel persistence-baseline` · `sentinel persistence` · `sentinel behavioral`

## [3.3.1] — 2026-10-25

### FIM / detection quality
- **Mode + ownership tracking** on every baselined file (FIM_MODE_CHANGE, FIM_OWNER_CHANGE)
- **SUID/SGID inventory** (`modules/fim_suid.py`): NEW_SUID, REMOVED_SUID, SUID_META_CHANGE
- **Real-time FIM** (`modules/fim_realtime.py`): single multi-path inotifywait process; polling fallback
- CLI: `python3 sentinel.py suid` · `python3 sentinel.py watch`
- `sentinel integrity` builds both content baseline and SUID inventory

## [3.3.0] — 2026-10-24

### Firewall (Phase 13.2)
- **Lockout guard**: refuses to block current/recent SSH operator IPs; `protect-operator` before hardening profiles
- **IPv6**: iptables path uses `ip6tables` for v6 targets; nft already dual-stack via `inet`
- Firewall actions logged into case system when available
- CLI: `firewall protect-operator`, `firewall operator-ips`

### Alerting
- Failed multi-channel delivery auto-enqueues to offline queue (flush via `sentinel offline flush`)


# Changelog

## 3.7.1 — 2026-10-24

### Phase 13.1 — Host Firewall enhanced
- CIDR blocks, apply-managed, enable/disable, lab_lockdown profile
- max_blocks safety, richer status/doctor
- response_actions.block_ip routes through modules.firewall
- setup.py + apply_firewall_cli wiring
- Cheatsheet PDF/MD refreshed

## 3.7.0 — 2026-10-24

### Phase 13 — Host Firewall Control Plane
- modules/firewall.py nft/iptables host FW manager

## 3.6.0 — 2026-10-24

### Phase 12 — Foundations
- tenants, policy auto_response, UEBA-lite

## 3.5.1 — 2026-10-24

Dual-connector pilot wire

## 3.0.0 — 2026-10-15

Plain source tree, multi-channel alerting, central server, Windows agent.
