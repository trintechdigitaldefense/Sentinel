# SENTINEL Security & Production-Readiness Audit

**Repository:** https://github.com/trintechdigitaldefense/Sentinel  
**Audit date:** 2026-10-26  
**Audited revision:** `27a353f` (tag **v3.14.2**, branch `main` at audit start)  
**Working branch for remediation:** `hardening/production-readiness`  
**Auditor role:** defensive security / Python maintenance (Milestone 1 inventory)

**Scope of execution in this audit environment:**
- Full tree inspection of latest clone from GitHub
- Static review of installer, dashboard, firewall/SSH, doctor, alerting touchpoints
- Attempted `pytest -q tests/` and `py_compile` on core modules
- **Not executed:** full Sentinel hunt on a production host, live firewall apply, live SIEM delivery, browser-based dashboard XSS campaign

This document does **not** claim Sentinel is production-ready. Status is **development / pilot candidate** until release gates in `docs/RELEASE_CHECKLIST.md` are evidenced.

---

## 1. Repository inventory (summary)

| Area | Location | Notes |
|------|----------|--------|
| Engine | `sentinel.py` (~3500 lines) | CLI + menu + hunt orchestration |
| Install | `install.sh`, `setup.py` | **Default path hard-resets git tree** |
| Modules | `modules/` (~86 Python modules) | Detection, deception, FW, SIEM, dashboard, cases, MSP |
| Tests | `tests/` (~30 files, ~1330 lines) | Unit/integration; collection currently **blocked** (see C-01) |
| CI | `.github/workflows/ci.yml` | ruff subset, py_compile subset, firewall smoke, pytest |
| Docs | `docs/`, PHASE*.md, README, INSTALL | Pilot/sales heavy; security audit was thin |
| Central/MSP | `sentinel_central/`, `modules/agent_keys.py` | Per-agent keys design present |
| Packaging | `Dockerfile`, `docker-compose.yml`, `requirements.txt` | Optional deps only (reportlab, requests) |

### Feature entry points (non-exhaustive)

| Feature | Entry | Privileges / side effects |
|---------|-------|---------------------------|
| Continuous hunt | `sentinel.py hunt` / menu 1,3 | Host scans, alerts, optional quarantine |
| FIM / SUID | `integrity`, `modules/fim_*` | Reads filesystem; writes baselines under `~/.sentinel` |
| Deception / canaries | `deception`, deploy paths | Writes decoy files under home/tmp |
| SSH / brute-force | `modules/brute_force.py` | May block IPs when `auto_block` true |
| Firewall | `modules/firewall.py` | Dry-run default; apply needs confirm |
| Real-time threats | `modules/realtime_threat.py` | Process/port/canary snapshot |
| Dashboard | `modules/dashboard_impl.py` | HTTP on configured bind; token auth |
| Doctor / go-live | `modules/doctor.py`, `go_live.py` | Read-only checks + config chmod repair |
| SIEM / Splunk | `modules/siem.py` | Outbound HTTP/file ship |
| Cases / evidence | `modules/cases*.py` | Local case store + export |
| Service install | `service-install` | systemd or background nohup |

---

## 2. Findings

### Critical

#### C-01 — SyntaxError: `from __future__` not first in several modules
- **Files:** `modules/agent_keys.py`, `modules/critical_alerts.py`, `modules/visibility.py` (and possibly others modified by prior “logify” edits that prepended `import logging`)
- **Evidence:** `pytest` collection fails:
  ```
  File "modules/agent_keys.py", line 7
    from __future__ import annotations
  SyntaxError: from __future__ imports must occur at the beginning of the file
  ```
- **Impact:** CI pytest job fails; package import of agent key paths broken; MSP key flows unusable until fixed.
- **Fix:** Move `from __future__ import annotations` to line 1 (after module docstring only). Ensure no imports precede it.
- **Regression test:** `python -m py_compile modules/agent_keys.py` + import in `tests/test_backup_keys_smb.py`.
- **Verification:** Observed collection ERROR in this environment (2026-10-26). **Not fixed in Milestone 1.**

#### C-02 — Installer defaults to destructive git reset and clean
- **Files:** `install.sh` (`sync_repo`: `git reset --hard`, `git clean -fd`); `setup.py` (`ensure_git_clean` resets unless `SENTINEL_KEEP_LOCAL=1`)
- **Evidence:** `install.sh` lines invoke hard reset by default; comments state “Always syncs to origin/main (hard reset)”.
- **Impact:** Routine reinstall/upgrade **discards uncommitted local changes and untracked files** without an explicit recovery workflow. Violates production upgrade safety and the project’s own non-negotiable rule against routine hard resets.
- **Fix:** Default to non-destructive `fetch` + fast-forward (or fail with instructions). Require explicit flag e.g. `SENTINEL_RECOVER_SYNC=1` for hard reset. Separate first install / upgrade / recovery paths. Never `git clean -fd` without typed confirmation.
- **Regression test:** Temp git repo with dirty file must survive default `install.sh` / `setup.py`.
- **Verification:** Static confirmation of scripts at `27a353f`. **Not fixed in Milestone 1.**

### High

#### H-01 — Dashboard control-mode toggle can re-enable controls with only the shareable token
- **File:** `modules/dashboard_impl.py` — `do_POST` path for `control-mode`
- **Evidence:** Comment in code: control-mode toggle allowed with token even in view-only mode so controls can be re-enabled.
- **Impact:** Anyone with the URL token can escalate from view-only to control (ACK criticals, run actions) without a separate operator secret.
- **Fix:** Require explicit admin credential or a separate control token; do not allow privilege elevation via the same viewer token; enforce `role` / `allow_control` server-side from config refresh, not client toggle alone without re-auth.
- **Regression test:** POST `/api/control-mode` with viewer token while `allow_control=false` must return 403.
- **Verification:** Static review only. **Untested in browser.**

#### H-02 — Class-level `allow_control = True` on HTTP handler
- **File:** `modules/dashboard_impl.py` — `_Handler.allow_control = True` (class attribute)
- **Impact:** If instance attribute is not set, Python falls back to class default **True**, opposite of safe config default `False`.
- **Fix:** Class default `False`; set instance from config only at server start.
- **Regression test:** Handler without instance override denies POST actions.

#### H-03 — Doctor “CLIENT-READY” verdict with only OK/WARN
- **File:** `modules/doctor.py` — `ready = fail == 0 and ok >= 8` then prints `CLIENT-READY`
- **Impact:** Missing heartbeat, inactive service, or unknown controls can still yield a “client ready” style message. Misleading for operators and sales.
- **Fix:** Require explicit production controls (service active, alert channel configured or acknowledged skip, no default secrets). Use statuses PASS/WARN/FAIL/UNKNOWN/NOT_APPLICABLE; never call unknown “verified”.
- **Regression test:** Fixture with inactive service must not produce CLIENT-READY / production-ready language.

#### H-04 — Auth token passed in query string
- **File:** `modules/dashboard_impl.py` — `?token=` on HTML and API links
- **Impact:** Tokens leak via access logs, browser history, Referer headers.
- **Fix:** Prefer `Authorization: Bearer` only for API; HttpOnly cookie or short-lived session after POST login for UI; redact token in logs.

### Medium

#### M-01 — CI Action pins are mutable tags (`actions/checkout@v4`, `setup-python@v5`)
- Prefer commit SHAs; least-privilege `permissions:` block missing.

#### M-02 — Ruff only checks a subset of modules (`E9,F821` on few files)
- Syntax regressions outside that set (e.g. agent_keys) are not caught by ruff step the same way.

#### M-03 — Progressive ban / auto_block defaults improved (v3.14.1) but need integration tests
- `auto_block` default False observed in `sentinel.py` defaults — good; progressive duration present — needs tests for duration scaling and dry-run.

#### M-04 — Evidence hash honesty documented (`docs/EVIDENCE_HASH.md`) — good; ensure sales copy does not overclaim chain-of-custody.

#### M-05 — Silent or debug-only exception handling still uneven across modules
- Prior partial logify; some `except Exception: pass` may remain in alerting paths.

### Low

#### L-01 — README / version messaging may lag rapid tag cadence (3.14.x); keep status as pilot, not “production-ready”.
#### L-02 — PHASE*.md and legacy wire scripts may confuse operators; document “do not run legacy stabilize/assemble”.

---

## 3. Test evidence (this environment)

| Check | Result |
|-------|--------|
| `git rev-parse HEAD` | `27a353f` |
| `python -m py_compile sentinel.py setup.py` | **Pass** (observed) |
| `pytest -q tests/` | **FAIL** — collection error C-01 (`agent_keys.py` SyntaxError) |
| Live dashboard / firewall apply / SIEM | **Not run** |

---

## 4. Milestone plan (do not skip gates)

1. **Milestone 1 (this PR):** Inventory + audit doc only.  
2. **Milestone 2:** Fix C-01, C-02 (installer non-destructive), H-01–H-03, dashboard defaults — separate commits/PRs.  
3. **Milestone 3:** Expand tests + CI (compile all modules, auth tests).  
4. **Milestone 4–6:** Remaining modules, README accuracy, release candidate — owner approval required for merge to `main`.

---

## 5. Explicit non-claims

- No claim that Sentinel is free of vulnerabilities.
- No claim that CI is green on `main` until C-01 is fixed and Actions are re-run.
- Multi-client isolation on central was previously assessed positively in external review; **not re-verified with runtime tests in this audit.**


## Milestone 2 remediation status (branch work)

| ID | Status on branch |
|----|------------------|
| C-01 | Fixed — `__future__` order in agent_keys, critical_alerts, visibility, webview |
| C-02 | Fixed — install/setup non-destructive by default; recovery only via `SENTINEL_RECOVER_SYNC=1` |
| H-01 | Mitigated — token cannot enable controls; only disable or confirm already-enabled |
| H-02 | Fixed — class default `allow_control = False` |
| H-03 | Mitigated — verdict no longer says CLIENT-READY |
| H-04 | Open — token still accepted via query string (prefer Bearer); deferred |


## Milestone 3 status

- CI expanded: compile all modules, future-import guard, ruff on modules/tests, install.sh syntax
- Tests: test_install_safe.py, expanded test_dashboard_authz.py
- docs/TESTING.md with reproducible commands


## Milestone 4 status

- self_defense baseline atomic + mode 0600
- alerting: log failures; atomic dedup store
- ransomware/honeyauth: reduced silent failures
- fim_realtime.visibility_status for incomplete realtime coverage
- regression tests added (not a full detection coverage proof)


## Milestone 5 status

- README rewritten: accurate status (pilot candidate), feature table with tested/partial labels, safe install path, security defaults, known limitations
- INSTALL.md: non-destructive upgrade; explicit recovery only
- SECURITY.md: reporting + defaults aligned with code
- VERIFY.md points at TESTING + release checklist
- No production-ready claim without RELEASE_CHECKLIST evidence


## Milestone 6 status

- Release candidate notes: docs/RELEASE_CANDIDATE.md (v3.14.6-rc1)
- RELEASE_CHECKLIST updated with PASS/PARTIAL/OPEN evidence
- Residual risks listed for human approval
- **No production-ready declaration**


## Milestone 7 status

- H-04 mitigated (Bearer/cookie preferred)
- CI F821 bp fixed
- Residual docs: docs/MILESTONE7_RESIDUALS.md
