# Phase 11 — Correlation, assisted AI, gated response

**TrinTech Digital Defense · Sentinel 3.5.0**  
Status: implemented 2026-10-24

## Honest scope

Phase 11 **starts** the previously deferred themes without claiming a full product rewrite:

| Deferred theme | Phase 11 reality |
|----------------|------------------|
| Multi-vendor correlation | Time/host correlation across connectors → bundles → optional case |
| AI core | Optional LLM summary **or** offline template; notes only, no auto-response |
| Autonomous response | **Gated** recommendations; execute requires `confirm=True` + `response.enabled` |
| Full cloud SIEM | **Not** built — remains deferred; central case sync from Phase 9 is the MSP surface |

## Modules

- `modules/correlation.py` — `correlate()`, `correlate_from_connectors()`, `promote_bundle_to_case()`
- `modules/fleet_correlate.py` — one-shot fleet helper with optional promote
- `modules/ai_assist.py` — `summarize_case()` offline or OpenAI-compatible API
- `modules/gated_response.py` — recommend / plan / explicit execute

## Config sketches

```json
{
  "ai": {
    "enabled": false,
    "api_key": "",
    "base_url": "https://api.openai.com/v1",
    "model": "gpt-4o-mini"
  },
  "response": {
    "enabled": false,
    "block_ip": false,
    "kill_process": false
  }
}
```

## Smoke

```bash
python3 scripts/phase11_smoke.py
```

## Still deferred

Full multi-tenant cloud SIEM replacement, silent autonomous response, deep TI enrichment, complex UEBA.
