# SENTINEL — Client Pilot Runbook (one page)

**TrinTech Digital Defense** · 1 host · 14-day pilot · Authorized defensive monitoring only

> Continuous host monitoring and early warning — canaries, shell detection, file integrity, SSH abuse blocking, clear alerts and reports — without a full SOC.

| Pilot — 1 host | Pilot + readout | Monthly (after) |
|----------------|-----------------|-----------------|
| **USD 450 / TTD 3,000** | **USD 650 / TTD 4,400** | **USD 200–350 / host** |

---

## Install & go-live (day 0)

1. **Written authorization** — host IP/scope, monitoring only, signed ROE  
2. **Install** — `git clone …/Sentinel.git && cd Sentinel && python3 setup.py`  
3. **Pilot check** — `python3 sentinel.py pilot`  
4. **Baselines** — `python3 sentinel.py integrity`  
5. **Canaries** — `python3 sentinel.py deception`  
6. **Always-on** — `python3 sentinel.py service-install` (or menu **1** continuous)  
7. **Field soak** — `python3 sentinel.py field-soak --confirm`  
8. **Alerts (pick one)** — WhatsApp in config **or** `siem splunk-configure --url … --token …`  
9. **Handover** — dashboard URL + token · critical ACK process · save `pilot_report.json`

## During the 14 days

- Leave continuous protection running  
- Client escalates only on **CRITICAL** (canary, shell, integrity)  
- Operator: `python3 sentinel.py critical status` → `critical ack <id>`  
- Optional weekly: `doctor` · `ops` · `field-soak`

## End of pilot (day 14)

- Re-run `pilot` + `field-soak`  
- Deliver PDF report + 30-minute readout  
- Convert to monthly if value is clear  

## In scope / out of scope

| In pilot | Not included |
|----------|--------------|
| 1 Linux host, FIM/SUID/persistence, canaries, continuous hunt, 1 alert channel, reports, 1 install + 1 readout | Multi-site fleet, 24/7 SOC, custom SIEM build, Windows estate, offensive testing, guaranteed prevention |

## Quick objections

| Concern | Response |
|---------|----------|
| Need a full SOC? | Early warning on the server you care about — not a SOC. |
| Lock us out? | Firewall dry-run by default; lockout guard protects operator SSH. |
| Can we review it? | Plain Python source; authorized defensive use only. |

PDF: [SENTINEL_One_Page_Runbook.pdf](SENTINEL_One_Page_Runbook.pdf)
