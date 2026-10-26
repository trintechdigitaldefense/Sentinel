# Release candidate notes — v3.14.6-rc1

**Date:** 2026-10-26  
**Git branch:** `hardening/production-readiness`  
**PR:** https://github.com/trintechdigitaldefense/Sentinel/pull/6  

## Intent

Ship a **pilot-candidate** hardening train: safer install, safer dashboard defaults, honest docs, stronger CI/regression.  
**Not** a declaration that Sentinel is free of vulnerabilities or ready for unsupervised production on all customer sites.

## What landed (Milestones 1–5)

1. Security audit + inventory + release gates docs  
2. Critical fixes: `__future__` import order; non-destructive install; dashboard control escalation denial; doctor verdict language  
3. Expanded CI + regression tests (compile-all, install safety, authz)  
4. Module hardening: self-defense baseline 0600/atomic; alerting queue/dedup; tripwire/honeyauth logging; FIM visibility status  
5. README / INSTALL / SECURITY accuracy  

## Acceptance tests run in Milestone 6 environment

| Command | Result |
|---------|--------|
| `pytest -q tests/` | **131 passed** |
| Compile `sentinel.py` + `setup.py` + all `modules/**/*.py` | **Pass** (88 files) |
| `bash -n install.sh` | **Pass** |
| Live firewall apply | **Not run** |
| Live SIEM / WhatsApp delivery | **Not run** |
| Full browser XSS suite | **Not run** |

## Residual risks (owner must accept or defer)

| ID | Risk | Recommendation |
|----|------|----------------|
| H-04 | Dashboard token in query string may leak via logs/Referer | Prefer Bearer-only / short-lived session before wide exposure |
| FW-LIVE | Firewall apply not CI-tested on real nft/iptables | Validate on disposable VM with console access before customer apply |
| ALERT-LIVE | Channel delivery not chaos-tested | Confirm WhatsApp/email/HEC on pilot host |
| DETECT-FP | Heuristic shell/tripwire false positives | Pilot with quiet hours + suppressions; treat as leads |
| CI-GHA | Local pytest ≠ GitHub Actions | Require green Actions on PR before merge |
| SECRET-OPS | Operators may still set weak dashboard passwords | Doctor checks when password key set; keep password auth optional |

## Rollback plan

1. Do **not** delete `~/.sentinel` data during rollback.  
2. Application code: check out previous known tag on `main` (e.g. pre-merge tag) or revert the merge commit.  
3. Re-run `python3 setup.py` (non-destructive) and `python3 sentinel.py doctor`.  
4. If service installed: `python3 sentinel.py service-install` after code rollback or restart service unit.  

## Merge recommendation

**Conditional merge to `main` after:**

1. Owner ticks sign-off on RELEASE_CHECKLIST  
2. GitHub Actions green on PR #6  
3. Optional: one friendly-host pilot smoke (doctor + hunt 10 minutes)  

**Do not** publish marketing as “production-ready” until remaining PARTIAL/OPEN gates are closed or explicitly accepted in writing.
