# Phase 0 — Discovery (Complete)

**Date:** 2026-10-24  
**Repo:** https://github.com/trintechdigitaldefense/Sentinel  
**Status:** Locked. All future work builds on the existing Sentinel v3.1 product line.

## Current inventory (v3.1)

### Core capabilities (shipped)
- File integrity monitoring (FIM) + persistence hunting
- Reverse-shell / suspicious process detection
- Canary deception (digital tripwires) + optional canary SMB share
- Multi-channel alerts (WhatsApp, email, webhook, syslog)
- Local dashboard with admin / viewer roles
- Plain-language PDF client reports + scheduled reports
- Encrypted backup / restore
- Windows agent + Linux systemd service
- Optional MSP central server with per-agent API keys (enroll / revoke)
- Docker packaging, CI, tests, VERIFY.md + SHA256SUMS
- Config schema validation, structured logging, quiet hours, dedup
- Response actions gated (default off): kill process, block IP, disable user
- Threat intel hooks (AbuseIPDB / OTX)
- Evidence export, watchdog, self-defense helpers

### Architecture notes
- Single-developer friendly Python CLI + `modules/` package
- Config-driven (`~/.sentinel/config.json`)
- Low external dependency preference
- Central server exists but isolation and operator multi-site experience are still thin
- Alerts exist; durable cases / assignment / status workflow do not
- Almost no external tool connectors (Wazuh, Defender, Fortinet, Sophos, etc.)

## Gaps identified
1. Central / multi-tenant isolation and audit trail are incomplete
2. No durable case management or triage workflow
3. No read-only connectors for client security tools
4. Dashboard is local HTML only — limited remote operator experience
5. Metrics / health for central and fleet still basic
6. Post-3.1 milestones were not locked in ROADMAP.md

## Decisions locked in Phase 0
- We improve the **existing** Sentinel product. We do **not** replace it with a separate cloud SIEM.
- Next work order:
  - **Phase 5** — Harden central: stronger tenant/agent isolation + audit events
  - **Phase 6** — First external connector (Wazuh preferred, or Sentinel’s own normalized events as reference)
  - **Phase 7** — Case / triage workflow + improved evidence export
- All code, docs, and commits go to this repository only.
- Synthetic / lab data only until isolation and authorization controls are proven.
- Response actions remain human-gated by default.

## Deliverable of Phase 0
This document + updated ROADMAP.md + README.md reflecting the post-3.1 direction.

*DEFEND. DETECT. DOMINATE.* 🇹🇹
