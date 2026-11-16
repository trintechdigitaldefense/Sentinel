# Release checklist (gates)

**Branch under review:** `remediation/production-security-hardening`  
**Source version label:** **v3.16.21** (from `setup.py`; not a published release or production approval)  
**Last historical acceptance run:** 2026-10-26 (results apply only to the revision tested then)  
**Current remediation verification:** GitHub Actions passed on branch head `2f4f032ad8a4b16b8118baef059f27d7cfd40fb6` (2026-11-16); owner approval and pilot validation remain open  

Legend: **PASS** = evidenced here · **PARTIAL** = automated only / incomplete · **OPEN** = not done · **N/A** = not applicable

| Gate | Status | Evidence |
|------|--------|----------|
| No unresolved **Critical** in SECURITY_AUDIT | **PARTIAL** | C-01, C-02 remediated on branch; confirm after merge to main + CI green |
| High-risk dashboard authz tests pass | **PASS** | `tests/test_dashboard_authz.py` in full suite |
| Install/upgrade preserves user data by default | **PASS** | Invalid JSON is preserved with a protected backup; disposable config tests and current CI passed |
| Firewall dry-run default + recovery in disposable VM | **PASS** | Isolated live nftables CI: apply/reapply, IPv4/IPv6 rules, unrelated-table preservation and rollback (2 passed) |
| High-severity alerts survive delivery failure + restart | **PARTIAL** | offline queue + critical store code/tests exist — **not** chaos-tested on live channels |
| Doctor does not claim production-ready / CLIENT-READY | **PASS** | Verdict language updated (M2) |
| Full CI suite passes | **PASS** | Python 3.10 and 3.12: 239 passed, 4 skipped on branch head `2f4f032` |
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
| Network central listeners refuse plaintext HTTP | **PASS** | TLS integration tests and generated installer HTTPS check-in with CA verification; plaintext network listeners fail closed |
| Agent credentials are unique, expiring, and protected in generated bundles | **PASS** | Expiry/revocation/rotation tests; bundle permissions and installer-to-central HTTPS check-in passed. SSH transfer itself is mocked in tests |
| Firewall events are written to case records | **PASS** | Firewall-to-case integration test passed on current branch |
| Setup does not mutate application source or overwrite invalid client config | **PASS** | Install-time source mutation removed; invalid config preservation and safe merge tests passed |
| Live firewall apply/rollback/lockout test in isolated VM | **PASS** | GitHub-hosted disposable runner: live nft apply/rollback (2 passed) and a real SSH session remained interactive through apply/reapply/rollback (1 passed) |
| Generated agent systemd lifecycle (install/check-in/crash restart/stop/start) | **PASS** | Dedicated Ubuntu systemd-PID-1 container: installer creates unit, HTTPS check-in, SIGKILL recovery, explicit restart, stop/start and sandbox assertions (1 passed) |
| Legacy agent-key migration handling | **PARTIAL** | Missing, malformed and expired credentials fail closed and are reported; rotation and status tests passed. Actual deployed agents still require owner-led one-at-a-time migration using `docs/AGENT_KEY_MIGRATION.md` |
