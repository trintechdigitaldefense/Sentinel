# Phase 6 — First Connector

**Status:** Implemented (2026-10-24)  
**Repo:** https://github.com/trintechdigitaldefense/Sentinel

## Goals achieved

1. **Connector contract** (`modules/connectors/base.py`)
   - `health_check()` → `ConnectorHealth`
   - `fetch_events(cursor, since, limit)` → `(list[NormalizedAlert], next_cursor)`
   - `normalize(raw)` → `NormalizedAlert | None`
   - Optional `acknowledge(cursor)` (default no-op)
   - Read-only only — no blocking / isolation / account actions

2. **Normalized alert schema**
   - `id`, `source`, `source_event_id`, `severity`, `title`, `occurred_at`, `received_at`
   - `status`, `asset_id`, `rule_id`, `detail`, `evidence_reference`, `raw_ref`, `extra`
   - Severity mapping covers text + Wazuh numeric levels

3. **Reference connector: Sentinel local**
   - Reads `~/.sentinel/data/alerts.log`
   - Pagination via line cursor
   - Works offline with zero external deps

4. **Wazuh skeleton**
   - Config / env: `url`, `user`, `password`, `verify_tls`, `agent_id`
   - Auth via `/security/user/authenticate`
   - Normalize common Wazuh alert shapes
   - Intended for lab / approved pilot only

5. **CLI + tests**
   - `modules/connectors/cli.py`
   - `tests/test_connectors_phase6.py`

## Quick use

```bash
# Health of local reference connector
python3 -c "from modules.connectors.cli import main; main([\"health\", \"--source\", \"sentinel_local\"])"

# Fetch normalized local alerts
python3 -c "from modules.connectors.cli import main; main([\"fetch\", \"--source\", \"sentinel_local\", \"--limit\", \"10\"])"

# Wazuh (lab) — credentials via env or flags
export WAZUH_URL=https://lab-wazuh:55000
export WAZUH_USER=readonly
export WAZUH_PASSWORD=...
python3 -c "from modules.connectors.cli import main; main([\"health\", \"--source\", \"wazuh\"])"
```

## Tests

```bash
pytest tests/test_connectors_phase6.py -q
```

## Design rules carried forward

- Synthetic / lab data until isolation is proven for a given source
- Never scrape undocumented endpoints
- Least-privilege service accounts only
- No autonomous response from connector input

## Next

Phase 7 — Case / triage workflow + stronger evidence export.
