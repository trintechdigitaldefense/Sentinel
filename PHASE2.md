# Phase 2 — Own the Deception Layer

**Goal:** Make Sentinel the only lightweight tool that does *active deception* cleanly for SMB / Caribbean managed service.

## Features

| # | Feature | Module |
|---|---------|--------|
| 6 | **Mirage fusion** | Fake services + banners + file canaries as one Mirage profile |
| 7 | **Adaptive decoys** | Industry packs: accounting, retail, medical, logistics, general |
| 8 | **Decoy interaction scoring** | Score how interesting a lure was (open / copy / modify / beacon) |
| 9 | **Memory / process canaries** | Detect suspicious process names and LOTL patterns |
| 10 | **Attacker timeline** | Reconstruct first touch to canary hits |

## Config

```json
"mirage": {
  "enabled": true,
  "industry": "general"
}
```

Industry: `general` | `accounting` | `retail` | `medical` | `logistics`

## Wire into engine

```bash
git pull
python3 restore_phase2.py   # builds modules/phase2.py from p2c1+p2c2
python3 wire_phase2.py      # patches sentinel.py (v2.3.0)
python3 sentinel.py phase2
python3 sentinel.py mirage --industry accounting
python3 sentinel.py score
python3 sentinel.py timeline
```

## CLI

| Command | Purpose |
|---------|---------|
| `sentinel mirage` | Deploy Mirage profile |
| `sentinel mirage --industry accounting` | Industry-specific decoys |
| `sentinel score` | Decoy interaction scores |
| `sentinel timeline` | Attacker timeline |
| `sentinel phase2` | Phase 2 self-check |

See `modules/phase2.py` and `wire_phase2.py`.
