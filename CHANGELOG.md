# Changelog

## Unreleased — supervised monitoring documentation and PDF serving hardening (2026-11-20)

- PR #21 merged to `main` as `d639b9d8beb17c64ad4904af281f81096feff4fe`: dashboard PDF serving rejects unsafe filenames, symlinked files/directories, and paths outside approved report locations.
- Added regression coverage for symlinked `data` and `reports` directories and generated-report paths.
- Validation on the PR commit: full local suite **310 passed, 1 skipped**; GitHub Actions passed on Python 3.10 and 3.12.
- Clarified Sentinel's operating model as supervised automated monitoring: continuous monitoring can run on a supported always-on host, while an authorised operator reviews alerts and controls response.
- No product version bump, release tag, production certification, or deployment approval is implied.
- Dashboard CSRF Origin/Host validation (#15), atomic runtime configuration writes (#16), remote-dashboard TLS verification (#17), and CSP hardening (#18) remain open.

## Unreleased — post-merge alert reliability (2026-11-17)

- PR #9 merged to `main` as `e80c09b`: reliable active-finding alert deduplication and delivery retry handling.
- Added persistent finding state separate from trusted detection baselines; atomic mode-0600 writes and thread/process locking.
- Serialized alert delivery per fingerprint; only confirmed delivery, durable queueing, or intentional suppression is treated as handled.
- Hardened offline queue writes/flush behavior and routed hunt-cycle maintenance retries through the unified alert router.
- Added lifecycle, concurrency, failure/retry, offline-queue, and email-compatibility regression coverage.
- Post-merge local verification: `python3 -m pytest -q` → 242 passed, 1 ReportLab deprecation warning (Python 3.12). PR #9 CI passed on Python 3.10 and 3.12.
- No product version bump or release tag is implied by this documentation update. Live channel delivery and production-host validation remain separate gates.

## [3.14.8] — 2026-10-27

## 3.16.21b — GitHub brand banner

- docs/assets/sentinel-github-banner.png for README / social preview

## 3.16.21 — dashboard reports + safe actions in view-only

- PDF GET endpoints verified (client + technical stream as application/pdf)
- Safe dashboard actions work without allow_control
- Mutating actions still need allow_control
- openPdf() helper; extra field-tool buttons

## 3.16.20 — multi-host agents + field evidence packs

- modules/multi_host.py: fleet status, prepare install bundle + optional keys
- modules/field_evidence.py: hashed zip of local + agent reports + soak
- field_soak includes multi_host step
- CLI: multi-host status|prepare, field-evidence [--soak]
- Fleet menu options 15–18

## 3.16.19 — menu renumber + SSH submenu

- Main menu sequential 1–25 (no gaps 23/24 out of order)
- New SSH brute-force submenu; nftables options under Firewall
- Suppressions + sanitize-subnets under Ops
- Invalid choice lists valid numbers; menu wiring tests

## 3.16.18 — nftables base ruleset + bad_hosts sets

- modules/nftables_rules.py: established/related, lo, ICMP limit, operator accept,
  high-risk port drops, SSH rate-limit, @bad_hosts timeout sets
- ensure_backend_ready / block_ip prefer set-based DROP
- CLI: nft-apply [--confirm], nft-list

## 3.16.17 — real DROP via root + nft/iptables

- drop_capabilities() / is_root() report whether live DROP is possible
- ensure_backend_ready() creates nft inet sentinel input chain or probes iptables
- block_ip requires root, prepares backend, verifies rule when possible
- SSH auto_block uses prepare path; clear errors when DROP unavailable
- CLI: firewall-prepare / drop-ready; doctor check_firewall_drop

## 3.16.16 — stronger SSH brute-force engine

- Broader auth failure markers + rhost/from IP extraction
- Configurable log window; last-scan snapshot for dashboard
- Alert SSH_BRUTE_CANDIDATE when auto_block is off
- Progressive bans, history, whitelist CIDR/prefix, unblock CLI
- auto_block remains off by default

## 3.16.15 — progressive SSH ban wired into check

- auto_block uses progressive_duration (2× each repeat, cap 24h)
- Default config documents max_block_duration + repeat_multiplier
- auto_block remains **off** by default (supervised)

## 3.16.14 — always-on status accuracy

- service-status reports monitoring when heartbeat is alive even without systemd unit
- Doctor soft-warns reboot persistence instead of implying total stop
- More debug logging in realtime_threat, firewall, fim_suid
- Docs overview version aligned

## 3.16.13 — heartbeat version + logging

- Heartbeat payload uses live Sentinel version (no more stale 2.9.9)
- heartbeat.alive set for dashboard hero accuracy
- Debug-log silent exceptions in phase5, hunt_cycle, go_live, doctor, brute_force, persistence

## 3.16.12 — autosubnet, suppressions in send_alert, pilot docs

- autosubnet skips docker/veth, clamps width, uses subnet_guard
- Learned suppressions applied in send_alert (non-critical)
- CLI: autosubnet, suppress-add, suppress
- README pilot deployment + docs/PILOT_DEPLOY.md

## 3.16.11 — CLI/menu polish

- Fix agent-key status handling
- Fleet menu uses pure numbers
- Doctor service check uses always_on status
- Clearer enroll_status when not enrolled

## 3.16.10 — always-on, RBAC, agent enroll UX

- Option 1 installs always-on hunt (systemd or background) so protection continues after menu exit
- service-stop / richer service-status via modules.always_on
- Dashboard control uses RBAC (allow_control + role=admin)
- agent-key issues per-agent API keys with enroll hint

## 3.16.9 — reliability gap fixes

- Doctor auto-sanitizes overly wide scan_subnets when possible
- Critical modules: silent except: pass → debug logging (dashboard, central, fleet, reports, agents)
- Version badges aligned to 3.16.9

## 3.16.8 — gap fixes (defaults, central auth, docs)

- Safe default scan subnet: office /24 only (no /8 or /12)
- Dashboard allow_control defaults to false (opt-in controls)
- Continuous protect runs subnet guard before discovery
- Central accepts shared token or per-agent API keys
- Optional central TLS via agent.tls_cert / agent.tls_key
- README / release checklist version aligned to 3.16.8

### Reports & dashboard

- Enhanced client PDF (logo, verdict badge, protection table, TrinTech contact)
- Dashboard logo + /api/assets/logo + one-click GET PDF
- Overview & cheatsheet doc

# Changelog

## [3.14.7] — 2026-10-26

### Milestone 7 — residual risk mitigations
- Dashboard: Bearer + cookie auth preferred (query token deprecated)
- Fix ruff F821 bp in ransomware_tripwire (CI green path)
- Realtime heuristic confidence + disclaimer
- Tests: alert chaos smoke, firewall dry-run contract, auth bearer/cookie

## [3.14.6] — 2026-10-26

### Milestone 6 — release candidate packaging
- docs/RELEASE_CANDIDATE.md + checklist evidence
- Acceptance pytest 131 passed (local RC env)

### Milestone 5 — docs and product presentation
- README: pilot-candidate status, truthful feature matrix, safe install
- INSTALL.md / SECURITY.md / VERIFY.md aligned with non-destructive defaults
- Cross-links to SECURITY_AUDIT, RELEASE_CHECKLIST, EVIDENCE_HASH

## [3.14.5] — 2026-10-26

### Milestone 4 — defensive module hardening
- self_defense: atomic baseline write + 0600
- alerting: no silent alert-log failure; atomic dedup + 0600
- ransomware_tripwire / honeyauth: logged failures
- fim_realtime.visibility_status() for incomplete coverage
- tests: self_defense, fim visibility, tripwire

## [3.14.4] — 2026-10-26

### Milestone 3 — CI and regression tests
- Compile-all + future-import guard in CI
- test_install_safe.py; expanded dashboard authz tests
- docs/TESTING.md

## [3.14.3] — 2026-10-26

### Production-readiness Milestone 2 (hardening branch)
- Fix C-01: future import order (agent_keys, critical_alerts, visibility, webview)
- Fix C-02: install/setup non-destructive by default; SENTINEL_RECOVER_SYNC=1 for recovery
- H-01/H-02: dashboard control-mode cannot enable controls via token; class default False
- H-03: doctor no longer prints CLIENT-READY
- tests: test_dashboard_authz.py; 120 passed in audit environment

## 3.14.2 — 2026-10-26

### Install path — no more stale trees
- Historical installer behavior and recovery notes are retained in this changelog for context; consult current INSTALL.md for the safe path.

## 3.14.1 — 2026-10-26

### Critical crash + security defaults
- Fix NameError true → True in init_config
- auto_block default False; config.json 0600; progressive SSH bans
- Dashboard loopback + viewer + allow_control False by default
- Doctor: config perms + default password; log silent excepts
- docs/EVIDENCE_HASH.md

## 3.14.0 — 2026-10-25

### Real-time threat detection (expanded)
- Detectors: reverse-shell cmdline, behavioral, risky ports, deleted exe, LD_PRELOAD, canary missing/empty, open criticals
- Hunt cycle emits alerts + critical store on hits
- CLI monitor / dashboard LIVE panel / menu item 21

## 3.13.4 — 2026-10-25

### Real-time threat level color coding
- CLI monitor: CLEAR green · WATCH cyan · ELEVATED yellow · HIGH red · CRITICAL magenta
- Severity lines colorized; dashboard badges/rows match

## 3.13.3 — 2026-10-25

### CLI monitor interval options
- monitor --interval N / -i N (min 3s)
- Presets: fast (5), normal (10), slow (30), hunt (60), idle (120)
- --once, --json, --quiet, --emit, --help

## 3.13.2 — 2026-10-25

### Real-time monitoring + restored controls toggle
- Dashboard live poll of /api/realtime?scan=1 (8–12s) without full page reload
- Restored controls switch (on/off) with reliable token API
- CLI continuous monitor: python3 sentinel.py monitor (or realtime-monitor)

## 3.13.1 — 2026-10-25

### Real-time threats + dashboard control toggle
- modules/realtime_threat.py — RS cmdline, behavioral, risky ports, criticals
- Dashboard panel + /api/realtime; faster refresh on HIGH/CRITICAL
- Control Enable/Disable toggle (POST /api/control-mode)
- CLI: python3 sentinel.py realtime

## 3.13.0 — 2026-10-25

### Full dashboard surface
- Wired: hunt, critical, alerts, visibility, SIEM, firewall, SSH blocks, blocklist, cases, go-live, service, quiet
- Control actions: doctor, ops, quiet on/off, field-soak, visibility, service-status, critical ACK
- APIs: /api/status, /api/critical, /api/go-live, /api/ops, /api/visibility, POST /api/action

## 3.12.1 — 2026-10-25

### Dashboard
- Critical alert ACK / ACK all from the UI (control mode)
- Go-live status panel from last go-live report
- API: GET /api/critical, GET /api/go-live, POST /api/critical/ack, POST /api/critical/ack-all
- View-only mode respects dashboard.allow_control: false

## 3.12.0 — 2026-10-25

### Host operational setup
- python3 sentinel.py go-live — one-shot baselines (FIM/SUID/persistence), canaries, alert ship channel, heartbeat
- --service optionally installs always-on hunt
- docs/GO_LIVE.md; menu item 21

## 3.11.1 — 2026-10-25

### Fixes
- field-soak: call threat_sim.run([...]) with a scenario list
- phase2: self-contained module
- dashboard version aligned to 3.11.1

## 3.11.0 — 2026-10-25

### Pilot readiness freeze
- field-soak command + docs/FIELD_SOAK.md
- docs/SALES_PACK.md — one-page runbook + fixed pilot pricing guide
- Explicit product focus: no feature sprawl until pilots complete

## 3.10.2 — 2026-10-25

### Splunk HEC integration
- Full HEC configure/health/batch/flush helpers in modules/siem.py
- CLI: siem splunk-configure, siem splunk env|health|flush

## 3.10.0 — 2026-10-25

### SIEM / centralized logging
- modules/siem.py — syslog, CEF, Splunk HEC, webhook, JSONL ship file
- Wired into AlertRouter + send_alert when alerting.siem.enabled
- CLI: siem status|test|cef-sample

## 3.9.1 — 2026-10-25

### Persistent critical alerts
- modules/critical_alerts.py — open critical events stored until operator ACK
- Quiet hours / hygiene cannot suppress critical types
- Hunt loop re-surfaces unacked criticals every loop
- CLI: critical status|ack|ack-all|resurface

## 3.9.0 — 2026-10-25

### Hunt loop, alerts, ops
- modules/hunt_cycle.py — structured cycle: heartbeat → FIM/process/SSH/outbound/users/cron → persistence → visibility → sensors → maintenance
- Per-check isolation + hunt_metrics.json
- send_alert routes through AlertRouter (dedup, channels, offline queue)
- modules/ops_status.py + CLI ops

## 3.8.0 — 2026-10-25

### Visibility (devices / processes / FIM / persistence)
- modules/visibility.py — unified inventory: ARP devices, process snapshot, FIM, SUID, persistence
- Network scan falls back to ARP when nmap missing/timeout
- Hunt loop refreshes device + process inventory each cycle

## 3.6.1 — 2026-10-25

### Menu + CLI wiring
- Interactive menu expanded: Detection, Firewall, Ops submenus
- Wired firewall / fw and cases CLI into sentinel.py

## 3.5.2 — 2026-10-25

### Pilot validation workflow
- Full phased pilot: preflight → baselines → deception → detection → service
- Go/No-Go checklist and ~/.sentinel/data/pilot_report.json

## 3.5.0 — 2026-10-25

### Product hygiene
- README feature matrix, CLI table, architecture
- docs/THREAT_MODEL.md — SMB-focused control mapping
- CI: ruff critical checks, module compile, firewall smoke, pytest

## 3.4.0 — 2026-10-25

### Persistence expansion + behavioral shells + self-FIM
- persistence_hunt: systemd timers/sockets, authorized_keys drift, LD_PRELOAD create/change, profile.d, rc files
- behavioral_shell: deleted /proc/pid/exe, TTY+TCP established, web-server→shell parent anomaly
- Self-FIM: tracks core modules + setup.py
- CLI: sentinel persistence-baseline, sentinel persistence, sentinel behavioral

## 3.3.1 — 2026-10-25

### FIM / detection quality
- Mode + ownership tracking on every baselined file
- SUID/SGID inventory (modules/fim_suid.py)
- Real-time FIM (modules/fim_realtime.py)
- CLI: sentinel suid, sentinel watch

## 3.3.0 — 2026-10-24

### Firewall (Phase 13.2)
- Lockout guard and IPv6 support
- Firewall actions logged into case system when available
- CLI: firewall protect-operator, firewall operator-ips

### Alerting
- Failed multi-channel delivery auto-enqueues to offline queue
