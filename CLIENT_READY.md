# Sentinel — Client-Ready Hardening Guide
**TrinTech Digital Defense** | Version 2.1 Client Package

This document defines what “client-ready” means for Sentinel and the minimum controls required before deployment on a customer network.

---

## 1. What “Client-Ready” Means

Sentinel is ready for **supervised commercial use** when all of the following are true:

| Requirement | Status Target |
|-------------|----------------|
| Token-authenticated multi-host agents | Required |
| File permissions locked (700/600) | Required |
| systemd service with restart policy | Required |
| Self-integrity baseline | Required |
| Log rotation | Required |
| Clean uninstall path | Required |
| Client-facing documentation | Required |
| Clear scope & limitations statement | Required |
| Tested on clean Linux environment | Required |
| Authorized-use only legal notice | Required |

**Not yet full hands-off product:**  
HTTPS agent channel, non-root mode, formal false-positive tuning, and long-term support SLAs remain supervised / roadmap items.

---

## 2. Full-Featured Protection Package (What Clients Get)

When delivered as part of TrinTech’s managed or co-managed offering:

### Core Engine (Sentinel)
- Continuous network device discovery & fingerprinting
- Reverse-shell & suspicious process detection
- SSH brute-force detection + automatic iptables blocking
- Realistic canary/decoy files (credentials, .env, SSH keys, DB configs)
- Real-time canary watcher
- Filesystem integrity monitoring (FIM)
- Persistence hunting (cron, users, SUID, systemd)
- Structured JSON alerts + optional email
- Professional PDF reports

### Companion Layers (Recommended Bundle)
- **Mirage** — additional honeypots & service deception
- **Full Network Audit & Mapping** — periodic deep recon
- **Bi-weekly security reports**
- **Weekly technical maintenance**

---

## 3. Pre-Deployment Checklist (Operator)

Before any client install:

- [ ] Confirm engagement is authorized in writing (ROE / SOW)
- [ ] Generate unique `shared_token` for this client
- [ ] Place same token in central + all agent `config.json`
- [ ] Restrict agent listener to internal network where possible
- [ ] Run `python3 sentinel.py integrity` to create FIM baseline
- [ ] Run `python3 sentinel.py deception` then verify canaries
- [ ] Generate test PDF report and review content
- [ ] Enable systemd services only after token & paths verified
- [ ] Document central IP, agent list, and token location for TrinTech ops

---

## 4. Hardening Controls Implemented

1. **Agent channel** — shared secret token (`X-Sentinel-Token` header); unauthorized agents receive 401
2. **Permissions** — `~/.sentinel` 700, config & logs 600
3. **systemd** — `sentinel-central.service` / `sentinel-agent.service` with `Restart=always`, `ProtectSystem=strict`
4. **Self-integrity** — hash check of critical files on startup
5. **Log rotation** — internal rotation + `/etc/logrotate.d/sentinel`
6. **Uninstall** — `python3 sentinel.py uninstall` stops services and removes data

---

## 5. Client Limitations (Must State)

- Not a replacement for EDR / antivirus / full SIEM
- Best for small–medium networks under TrinTech supervision
- Agent communication is token-protected but not yet TLS by default
- Outbound connection monitoring may be limited on restricted environments (e.g. some containers / Termux)
- Continuous nmap-based discovery should be scoped to agreed subnets

---

## 6. Support Model

| Item | Included |
|------|----------|
| Bi-weekly written reports | Yes (package) |
| Weekly technical maintenance | Yes (package) |
| Alert triage | Yes (managed) |
| Emergency response | As defined in SOW |
| Self-hosted only (no TrinTech ops) | Not recommended for production clients |

---

## 7. Legal

For **authorized defensive use only**.  
Unauthorized access to computer systems is illegal under the Trinidad & Tobago Cybercrimes Act and applicable international law.

---

**TrinTech Digital Defense** 🇹🇹  
Protecting Caribbean businesses through practical security visibility.
