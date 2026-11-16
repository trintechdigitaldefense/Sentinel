# Release checklist (gates)

**Branch under review:** `remediation/production-security-hardening`  
**Source version label:** **v3.16.21** (from `setup.py`; not a published release or production approval)  
**Last historical acceptance run:** 2026-10-26 (results apply only to the revision tested then)  
**Current remediation verification:** pending CI and review on this branch  

Legend: **PASS** = evidenced here · **PARTIAL** = automated only / incomplete · **OPEN** = not done · **N/A** = not applicable

| Gate | Status | Evidence |
|------|--------|----------|
| No unresolved **Critical** in SECURITY_AUDIT | **PARTIAL** | C-01, C-02 remediated on branch; confirm after merge to main + CI green |
| High-risk dashboard authz tests pass | **PASS** | `tests/test_dashboard_authz.py` in full suite |
| Install/upgrade preserves user data by default | **PARTIAL** | Remediation now stops on invalid JSON and preserves a backup; current branch tests/CI pending |
| Firewall dry-run default + recovery in disposable VM | **PARTIAL** | CI `firewall_smoke.py` dry-run only — **no live apply VM in this run** |
| High-severity alerts survive delivery failure + restart | **PARTIAL** | offline queue + critical store code/tests exist — **not** chaos-tested on live channels |
| Doctor does not claim production-ready / CLIENT-READY | **PASS** | Verdict language updated (M2) |
| Full CI suite passes | **OPEN** | Historical Actions results on `38f661c` do not validate this remediation branch; await current PR checks |
| Install/upgrade/rollback/uninstall docs verified | **PASS** (doc review) | INSTALL.md M5; uninstall command documented |
| No real secrets committed | **PARTIAL** | New bundles use per-agent keys in 0600 sidecar files; review generated artifacts and CI secret scanning on this branch |
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


## Current remediation-specific gates

| Gate | Status | Evidence required |
|------|--------|-------------------|
| Network central listeners refuse plaintext HTTP | **OPEN** | Current branch CI plus TLS integration test; certificate-backed deployment validation |
| Agent credentials are unique, expiring, and protected in generated bundles | **OPEN** | Current branch CI; verify enrollment, expiry, revocation, and bundle transfer end-to-end |
| Firewall events are written to case records | **OPEN** | Current branch CI and evidence-pack inspection |
| Setup does not mutate application source or overwrite invalid client config | **OPEN** | Current branch CI and disposable upgrade test |
| Live firewall apply/rollback/lockout test in isolated VM | **OPEN** | Disposable VM evidence; never infer from dry-run smoke test |
| Generated agent systemd lifecycle (install/check-in/crash restart/stop/start) | **OPEN** | Dedicated systemd-PID-1 CI container must pass; service lifecycle is distinct from sentinel-hunt |
| Legacy agent-key migration handling | **PARTIAL** | Legacy records fail closed and are reported; owner must migrate actual deployed agents one at a time using `docs/AGENT_KEY_MIGRATION.md` |
