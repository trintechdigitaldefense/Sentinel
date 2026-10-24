# Phase 5 — Central Hardening

**Status:** Implemented (2026-10-24)  
**Repo:** https://github.com/trintechdigitaldefense/Sentinel

## Goals achieved

1. **Agent isolation**
   - `client_id` is always derived from the verified agent key.
   - Request body `client_id` is ignored for event/heartbeat ingest.
   - Agents can only read their own events; master can read any.

2. **Fail-closed authorization**
   - Master key is required for enroll, revoke, list clients, list audit.
   - Master key is **rejected** on agent data paths (`/v1/events`, `/v1/heartbeat`).
   - Invalid / revoked / missing keys return 401.

3. **Audit trail**
   - New `audit_events` table records enroll, revoke, auth failures, list actions, event ingest.
   - Secrets are never written to audit rows.
   - `GET /v1/audit` (master only) returns recent records.

4. **Supporting changes**
   - `modules/agent_keys.py`: added `resolve_agent_id()` for key-only auth.
   - Payload size limit (1 MiB) on inbound JSON.
   - Security headers on all responses.
   - Tests: `tests/test_central_phase5.py`

## How to run

```bash
python3 -m sentinel_central.server --port 8443 --master-key YOUR_SECRET
```

Enroll (master key):
```bash
curl -X POST https://host:8443/v1/enroll \
  -H "X-API-Key: YOUR_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"client-site-1"}'
```

Agent event (agent key only):
```bash
curl -X POST https://host:8443/v1/events \
  -H "X-API-Key: AGENT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"title":"Canary hit","severity":"HIGH"}'
```

Audit (master only):
```bash
curl https://host:8443/v1/audit -H "X-API-Key: YOUR_SECRET"
```

## Tests

```bash
pip install -r requirements.txt pytest
pytest tests/test_central_phase5.py -q
```

## Next

Phase 6 — First read-only external connector (Wazuh preferred).
