# SENTINEL Feature Inventory (Milestone 1)

**Revision:** 27a353f / v3.14.2  
**Generated:** 2026-10-26  

Status labels: **Implemented** (code present) · **Tested** (automated test file exists) · **Experimental** · **Unknown** (no runtime proof in this audit)

| Capability | Module / entry | Status | Tests |
|------------|----------------|--------|-------|
| CLI menu | `sentinel.py` | Implemented | smoke partial |
| Hunt loop | `hunt_cycle.py` | Implemented | `test_hunt_cycle.py` |
| FIM baseline | fim modules | Implemented | limited |
| SUID tracking | `fim_suid.py` | Implemented | limited |
| Persistence hunt | `persistence_hunt.py` | Implemented | `test_persistence_behavioral.py` |
| Behavioral shell | `behavioral_shell.py` | Implemented | same |
| Realtime threat snapshot | `realtime_threat.py` | Implemented | limited |
| Brute-force SSH | `brute_force.py` | Implemented | `test_brute_force.py` |
| Firewall control plane | `firewall.py` | Implemented (dry-run default) | `test_firewall.py`, smoke script |
| Firewall intel rules | `firewall_intel.py` | Implemented | `test_firewall_intel.py` |
| Dashboard HTTP UI | `dashboard_impl.py` | Implemented | **auth tests missing** |
| RBAC helpers | `rbac.py` | Implemented | incomplete wiring tests |
| Doctor health | `doctor.py` | Implemented | no dedicated strict readiness test |
| Go-live bootstrap | `go_live.py` | Implemented | `test_go_live.py` |
| Critical alerts store | `critical_alerts.py` | Implemented | `test_critical_alerts.py` (blocked by C-01 imports?) |
| Alerting channels | `alerting.py` | Implemented | `test_alerting.py` |
| SIEM / Splunk | `siem.py` | Implemented | `test_siem.py`, `test_splunk_hec.py` |
| Cases | `cases*.py` | Implemented | phase tests |
| Agent keys (MSP) | `agent_keys.py` | Implemented | **broken SyntaxError C-01** |
| Deception canaries | engine + modules | Implemented | field_soak / threat_sim |
| Ransomware tripwire | `ransomware_tripwire.py` | Implemented | phase tests |
| Watchdog / deadman | `watchdog.py`, `deadman.py` | Implemented | limited |
| Auto response | `auto_response.py` | Implemented (off by default) | `test_response_actions.py` |
| Installer | `install.sh` / `setup.py` | Implemented | **destructive default C-02** |

Update this table when Milestone 2–3 land.
