# SENTINEL Feature Inventory

**Snapshot revision:** `e80c09b5a1cc461ed7d598cea9c1c5b2ec0c58ae` (PR #9 merged to `main`)  
**Updated:** 2026-11-17

This is a repository-level inventory, not a certification of detection coverage or operational readiness. “Automated tests” means regression tests exist and pass in the recorded suite; it does not mean every deployment path or external integration has been field-validated.

| Capability | Main implementation | Evidence in repository | Scope / limitation |
|---|---|---|---|
| CLI and hunt orchestration | `sentinel.py`, `modules/hunt_cycle.py` | Full suite; hunt-cycle tests | Host-specific behavior depends on OS permissions and available utilities |
| File integrity and visibility | `modules/fim_*.py`, `modules/visibility.py` | FIM and visibility tests | Realtime coverage depends on `inotify-tools`; polling/visibility can be incomplete |
| Persistence hunting | `modules/persistence_hunt.py`, `modules/finding_state.py` | `tests/test_alert_dedup.py`, persistence tests | Heuristic findings require operator review |
| Realtime threat snapshot | `modules/realtime_threat.py` | Realtime and alert regression tests | Heuristics can produce false positives |
| SSH brute-force monitoring | `modules/brute_force.py` | Brute-force and progressive-ban tests | Automatic blocking remains opt-in |
| Firewall control plane | `modules/firewall.py`, `modules/nftables_rules.py` | Dry-run and firewall contract tests | Live apply is not established by unit tests; confirmation and suitable privileges are required |
| Dashboard and access controls | `modules/dashboard_impl.py`, RBAC helpers | Dashboard authorization and PDF tests | Browser-level security testing and exposed-network deployment review remain separate |
| Multi-channel alert routing | `modules/alerting.py` | Alerting, email compatibility, concurrency tests | Real third-party delivery is not proven by mocked/unit tests |
| Active-finding deduplication | `modules/finding_state.py`, `modules/alerting.py` | `tests/test_alert_dedup.py`, `tests/test_alert_concurrency.py`, `tests/test_alert_engine_concurrency.py` | Finding state is notification state, not a trusted detection baseline |
| Offline alert queue | `modules/phase4.py`, `modules/hunt_cycle.py` | `tests/test_offline_queue.py`, `tests/test_queued_alert_delivery.py` | A queued item is durable locally; eventual external receipt still depends on channel availability |
| Critical alert persistence | `modules/critical_alerts.py` | Critical-alert tests | Operator acknowledgement and incident handling remain operational responsibilities |
| SIEM / Splunk HEC | `modules/siem.py` | SIEM/HEC tests | Live credentials, endpoint reachability, and ingestion require environment-specific validation |
| Central / remote agents | `modules/central_agent.py`, `modules/remote_agent.py`, `modules/agent_keys.py` | Agent, enrollment, central API tests | Requires explicit network, key-management, and deployment configuration |
| Evidence and client reporting | `modules/field_evidence.py`, `modules/client_report.py`, `modules/technical_report.py` | Evidence/report tests | Hashes support integrity checking; they are not, by themselves, a legal chain-of-custody guarantee |
| Installer and health checks | `install.sh`, `setup.py`, `modules/doctor.py` | Installer safety and doctor tests | “Doctor OK” is not a production certification |

## PR #9 — alert reliability details

- Finding fingerprints are persisted under `$SENTINEL_DIR/data/finding_state_<namespace>.json`, independently of trusted detection baselines.
- Finding-state files and lock files are created with restrictive permissions; state updates use temporary files and atomic replacement.
- Alert delivery attempts are serialized per alert fingerprint, with thread and process locking around shared deduplication state.
- Failed or unconfirmed sends remain eligible for retry rather than being marked handled merely because a router returned a generic result.
- Offline queue flushes retain entries that are not confirmed delivered and use the unified alert router retry path.
- The tests cover active → unchanged → resolved → recurring/changed findings, failed-send retry, concurrency, queue retention, and compatibility paths.

## Verification snapshot

At the merge revision, PR #9 GitHub Actions passed on Python 3.10 and 3.12. A post-merge local run on Python 3.12 completed with **242 passed and 1 ReportLab deprecation warning**. See [TESTING.md](TESTING.md) for exact scope.

## Status language

- **Implemented:** code path is present.
- **Automated tests:** regression coverage exists and passed in the recorded test run.
- **Operationally validated:** requires separate evidence from a controlled target environment; it is not inferred from unit tests.

Do not interpret this inventory as proof of exhaustive detection, live alert delivery, safe firewall application on every host, or production certification.
