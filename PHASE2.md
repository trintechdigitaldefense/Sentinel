# Phase 2 — Own the Deception Layer

**Goal:** Make Sentinel the only lightweight tool that does *active deception* cleanly for SMB / Caribbean managed service.

## Features

| # | Feature | Module |
|---|---------|--------|
| 6 | **Mirage fusion** | Fake services + banners + file canaries as one “Mirage” profile |
| 7 | **Adaptive decoys** | Industry packs: accounting, retail, medical, logistics, general |
| 8 | **Decoy interaction scoring** | Score how interesting a lure was (open / copy / modify / beacon) |
| 9 | **Memory / process canaries** | Detect suspicious process names & LOTL patterns beyond files |
| 10 | **Attacker timeline** | Reconstruct first touch → lateral → canary hits |

## Config additions

```json
"mirage": {
  "enabled": true,
  "industry": "general",
  "fake_services": true,
  "adaptive_decoys": true,
  "interaction_scoring": true,
  "process_canaries": true,
  "timeline": true
}
```

Industry values: `general` | `accounting` | `retail` | `medical` | `logistics`

## CLI

| Command | Purpose |
|---------|---------|
| `sentinel mirage` | Deploy Mirage profile (fused deception) |
| `sentinel mirage --industry accounting` | Industry-specific decoys |
| `sentinel score` | Show decoy interaction scores |
| `sentinel timeline` | Show attacker timeline |
| `sentinel phase2` | Phase 2 self-check |

## Integration

```python
from modules.phase2 import (
    mirage_deploy, score_interaction, process_canary_scan,
    timeline_record, timeline_report, adaptive_decoy_set,
    phase2_self_check,
)
```

Wire:
- `deploy_deception` → call `mirage_deploy` or use adaptive set
- Canary events → `score_interaction` + `timeline_record`
- `process_scan` → also `process_canary_scan`
- CLI: `mirage`, `score`, `timeline`, `phase2`

See `modules/phase2.py`.
