# SENTINEL — Post-pilot roadmap (demand-driven)

**Rule:** Do not build the rows below until a **paid or friendly pilot** produces the signal in the left column.

Feature freeze holds at **v3.12.x** for go-live / pilot / field-soak / sales pack.

---

## Decision table

| If pilots show… | Then build… | Why | Rough scope |
|-----------------|-------------|-----|-------------|
| **“We have 5 servers”** | Multi-host MSP polish: **per-agent keys**, central status, enroll/revoke | Shared token does not scale; one compromised agent must not unlock the fleet | Agent identity, key issue/rotate/revoke, central inventory of last-seen + open criticals |
| **“Boss wants a screen”** | Dashboard **RBAC**: admin vs **client view-only** | Owners want visibility without control of block/quarantine | Login roles, hide control actions for viewer, read-only API |
| **“We need paper for audit”** | Heavier **PDF trends** + **signed evidence** packaging | Regulators / insurers / boards want period comparisons and integrity | Trend charts vs prior period, hash-chained evidence zip, optional signature |
| **Nothing yet** | **Do not add features** — tighten delivery and support notes | Avoid sprawl; improve install clarity and handoff | GO_LIVE, RUNBOOK, SALES_PACK, field-soak checklist only |

---

## Current delivery path (no new modules)

```bash
python3 setup.py
python3 sentinel.py go-live --service
python3 sentinel.py pilot
python3 sentinel.py field-soak --confirm
python3 sentinel.py dashboard-url
```

Sales: [SALES_PACK.md](SALES_PACK.md) · [RUNBOOK_ONE_PAGE.md](RUNBOOK_ONE_PAGE.md) · [GO_LIVE.md](GO_LIVE.md)

---

## When a signal appears

1. Write it down (client quote + host count + date).  
2. Open a scoped milestone (one row from the table only).  
3. Ship behind existing menu/CLI — no second product.  
4. Re-run pilot + field-soak on a friendly host before the next paid deploy.

---

## Explicitly out of scope until later

- Full SOC / SIEM replacement marketing  
- Offensive tooling  
- Guaranteed prevention / “unblockable” claims  
- Large Windows estate as primary (Linux host pilot first)
