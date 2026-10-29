# Release checklist (gates)

**Branch under review:** `hardening/production-readiness`  
**Candidate version label:** **v3.16.8** (not tagged on `main` until owner approval)  
**Last acceptance run (this environment):** 2026-10-26  

Legend: **PASS** = evidenced here · **PARTIAL** = automated only / incomplete · **OPEN** = not done · **N/A** = not applicable

| Gate | Status | Evidence |
|------|--------|----------|
| No unresolved **Critical** in SECURITY_AUDIT | **PARTIAL** | C-01, C-02 remediated on branch; confirm after merge to main + CI green |
| High-risk dashboard authz tests pass | **PASS** | `tests/test_dashboard_authz.py` in full suite |
| Install/upgrade preserves user data by default | **PASS** (static + unit) | `install.sh` / `setup.py` non-destructive; `tests/test_install_safe.py` |
| Firewall dry-run default + recovery in disposable VM | **PARTIAL** | CI `firewall_smoke.py` dry-run only — **no live apply VM in this run** |
| High-severity alerts survive delivery failure + restart | **PARTIAL** | offline queue + critical store code/tests exist — **not** chaos-tested on live channels |
| Doctor does not claim production-ready / CLIENT-READY | **PASS** | Verdict language updated (M2) |
| Full CI suite passes | **PASS** (Actions on hardening branch) | Local pytest 138+; **GitHub Actions success on `38f661c`** (runs 40424099269 / 40424094495) |
| Install/upgrade/rollback/uninstall docs verified | **PASS** (doc review) | INSTALL.md M5; uninstall command documented |
| No real secrets committed | **PASS** (spot check) | No live tokens in tree in this audit pass |
| README claims match tested implementation | **PASS** (doc review) | M5 README truthful matrix |
| Known limitations documented | **PASS** | README + SECURITY_AUDIT |
| Owner-reviewed RC + rollback plan | **OPEN** | Awaiting human sign-off below |

## Owner sign-off (required before merge to `main` and any production tag)

- [ ] Product owner reviewed SECURITY_AUDIT residual risks  
- [ ] GitHub Actions CI green on this PR  
- [ ] Pilot host dry-run completed (doctor + go-live + one hunt cycle)  
- [ ] Rollback plan understood (previous tag / `git merge --ff-only` inverse)  

**Signature / date:** __________________  

This checklist does **not** by itself authorize a “production-ready” marketing claim.
