# Phase 4 — Hard to Copy

**Goal:** Features competitors cannot easily replicate — regional depth + response + forensics + offline resilience.

## Features

| # | Feature |
|---|--------|
| 16 | **Behavioral baseline** — learn normal procs/users/ports; flag deviations |
| 17 | **Caribbean threat pack** — T&T / regional ports, paths, process IOCs |
| 18 | **Response playbooks** — step-by-step for REVERSE_SHELL, canary, SSH, etc. |
| 19 | **Evidence pack** — zip of logs/baselines for incident handoff |
| 20 | **Offline mode** — queue alerts when network is down |

## Wire

```bash
git pull
python3 restore_phase4.py
python3 wire_phase4.py
python3 sentinel.py phase4
python3 sentinel.py baseline
python3 sentinel.py caribbean
python3 sentinel.py playbook REVERSE_SHELL
python3 sentinel.py evidence --hours 24
```

## CLI

| Command | Purpose |
|---------|--------|
| `sentinel baseline` | Build behavioral baseline |
| `sentinel baseline check` | Compare live state to baseline |
| `sentinel caribbean` | Caribbean / T&T threat pack scan |
| `sentinel playbook` | List playbooks |
| `sentinel playbook REVERSE_SHELL` | Show response steps |
| `sentinel evidence` | Evidence pack (zip) |
| `sentinel offline` | Offline queue status |
| `sentinel offline flush` | Flush queue (+ WhatsApp if wired) |
| `sentinel phase4` | Self-check |

*TrinTech Digital Defense 🇹🇹*
