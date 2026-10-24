# Changelog

## 3.5.1 — 2026-10-24

### Dual-connector pilot wire
- `modules/dual_pilot.py` + `scripts/dual_connector_pilot.py` (Sentinel-local + Wazuh)
- Correlation fix: `asset_id` / `occurred_at` host+time keys
- Default window 45m; lab synthetic alerts when Wazuh unreachable
- Lab AI key via `--ai-key` (offline default)

## 3.5.0 — 2026-10-24

### Phase 11 — Correlation · AI assist · gated response
- correlation / fleet_correlate / ai_assist / gated_response

## 3.4.0 — 2026-10-24

### Phase 10 — Operational cadence

## 3.3.0 — 2026-10-24

### Phase 9 — MSP daily use

## 3.2.1 — 2026-10-24

### Phase 8 — Ship-ready wire

## 3.2.0 — 2026-10-24

Phases 0–7 on existing Sentinel engine.

## 3.1.0 — 2026-10-15

Trust, MSP keys, backup/restore, Docker, CI.

## 3.0.0 — 2026-10-15

Plain source tree, multi-channel alerting, central server, Windows agent.
