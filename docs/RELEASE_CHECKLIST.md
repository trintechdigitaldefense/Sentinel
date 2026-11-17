# SENTINEL release checklist

**Current reviewed revision:** `933343c108d8e3d1cb42cfe9fc59378449896534` (`main`; PRs #14, #13, and #12 merged)  
**Updated:** 2026-11-17  
**Product status:** **pilot candidate**; no production release, certification, or deployment approval is declared by this checklist.

Legend: **PASS** = current evidence recorded · **PARTIAL** = automated/static evidence only · **OPEN** = evidence or owner decision still required.

## Security-hardening milestone — 2026-11-17

**Milestone outcome: SUCCESSFUL SECURITY-HARDENING MILESTONE.** The recent merged changes strengthen dashboard authentication and output handling, installer configuration safety, and offline alert-queue reliability. This milestone records progress; it is **not** a production-readiness declaration.

| Change | Record |
|---|---|
| PR #14 — offline queue overflow handling | Merged; rejects new queue entries at capacity rather than discarding older unconfirmed alerts. Merge commit: `7f20f544da56733da61824c8bdd7ffc9d08d8218`. |
| PR #13 — installer configuration preservation | Merged; adds guarded reads and atomic installer configuration writes with regression coverage. Merge commit: `91518fa75f877fb6b876add5260e4fd5771d5652`. |
| PR #12 — dashboard authentication and XSS hardening | Merged; improves viewer/admin separation, session handling, safe rendering, and security headers, with browser regression coverage. Merge commit: `933343c108d8e3d1cb42cfe9fc59378449896534`. |
| Combined-main regression suite | User-confirmed on exact `main` revision above: `python3 -m pytest -q` → **263 passed, 1 skipped, 1 warning in 72.81s**. The warning is a ReportLab deprecation warning involving `ast.NameConstant`; no test failed. |

The test result is automated regression evidence. It does not establish live deployment safety, real alert delivery, customer-host behavior, remote TLS configuration, or independent security approval.

## Remaining dashboard and deployment security work

The following four items remain **OPEN** and are tracked separately:

| Item | Status | Tracking |
|---|---|---|
| Add CSRF Origin/Host validation to cookie-authenticated state-changing dashboard requests | **OPEN** | [#15 — dashboard Origin/Host validation](https://github.com/trintechdigitaldefense/Sentinel/issues/15) |
| Implement atomic runtime dashboard configuration writes | **OPEN** | [#16 — atomic runtime configuration writes](https://github.com/trintechdigitaldefense/Sentinel/issues/16) |
| Require and verify properly configured TLS for remote dashboard access | **OPEN** | [#17 — remote dashboard TLS](https://github.com/trintechdigitaldefense/Sentinel/issues/17) |
| Reduce CSP reliance on `'unsafe-inline'` | **OPEN** | [#18 — CSP hardening](https://github.com/trintechdigitaldefense/Sentinel/issues/18) |

Closing these issues requires implementation and regression evidence. Before Sentinel's status is advanced, a reviewer independent of the implementation must verify the changes and evidence; issue closure or passing automated tests alone is not sufficient.

## Current release gates

| Gate | Status | Current evidence / remaining work |
|---|---|---|
| PRs #14, #13, and #12 merged | **PASS** | Merge commits recorded in the milestone table above; current `main` is `933343c108d8e3d1cb42cfe9fc59378449896534`. |
| Combined-main local regression suite | **PASS** | Python 3.12: 263 passed, 1 skipped, 1 ReportLab deprecation warning; user-confirmed on exact current `main`. |
| Offline queue capacity handling | **PASS** (automated) | Queue overflow rejects the new entry and preserves existing unconfirmed entries; live restart/soak evidence remains separate. |
| Installer configuration preservation | **PASS** (automated/static) | Symlink/special-file rejection and atomic installer writes have regression coverage; still validate upgrades on supported target platforms. |
| Dashboard authentication and XSS hardening | **PARTIAL** | PR #12 merged with browser regression coverage and security headers. CSRF validation remains OPEN (#15), CSP still needs hardening (#18), and remote-access TLS must be verified (#17). |
| CSRF Origin/Host validation | **OPEN** | Tracked in [#15](https://github.com/trintechdigitaldefense/Sentinel/issues/15). |
| Runtime dashboard configuration writes | **OPEN** | Runtime `_save_cfg()` still needs atomic-write protection; tracked in [#16](https://github.com/trintechdigitaldefense/Sentinel/issues/16). |
| Remote dashboard TLS configuration | **OPEN** | Remote access must use a properly configured TLS reverse proxy and secure session cookies; tracked in [#17](https://github.com/trintechdigitaldefense/Sentinel/issues/17). |
| Content Security Policy hardening | **OPEN** | Reduce/remove `'unsafe-inline'` with browser regressions; tracked in [#18](https://github.com/trintechdigitaldefense/Sentinel/issues/18). |
| Independent verification of remaining security work | **OPEN** | An independent reviewer must verify implementation, test evidence, and deployment requirements before status promotion. |
| Firewall dry-run behavior | **PARTIAL** | Dry-run/contract tests exist; no live apply validation on a disposable VM is recorded here. |
| Live alert channel delivery and receipt | **OPEN** | No real recipient, WhatsApp, webhook, syslog, or SIEM delivery test is claimed. |
| Offline queue across real host restart / power loss | **PARTIAL** | Automated persistence/queue tests exist; field restart/soak evidence is still needed. |
| Detection coverage and false-positive rate | **OPEN** | Requires representative pilot telemetry and operator review. |
| Current security audit / residual-risk review | **PARTIAL** | `SECURITY_AUDIT.md` is a historical audit snapshot; complete a fresh review against current `main`. |
| Secrets and deployment configuration review | **OPEN** | Recheck target-specific secrets, credentials, network exposure, and access controls before each pilot. |
| Operational validation, owner sign-off, and rollback rehearsal | **OPEN** | Record the approved pilot scope, complete operational checks, and rehearse rollback. |

## Required before a customer pilot

- [ ] Review the current code and historical findings in [SECURITY_AUDIT.md](SECURITY_AUDIT.md); record disposition of each remaining risk.
- [ ] Complete issues [#15](https://github.com/trintechdigitaldefense/Sentinel/issues/15), [#16](https://github.com/trintechdigitaldefense/Sentinel/issues/16), [#17](https://github.com/trintechdigitaldefense/Sentinel/issues/17), and [#18](https://github.com/trintechdigitaldefense/Sentinel/issues/18).
- [ ] Obtain independent review of the four security changes and their test evidence.
- [ ] Validate install, upgrade, backup, and rollback on a disposable supported host.
- [ ] Run `doctor`, confirm intended baselines/canaries, and observe a supervised hunt cycle.
- [ ] Verify alert routing with an explicitly approved test endpoint/recipient; record delivery and queue retry evidence.
- [ ] Validate firewall behavior in dry-run first; live apply only with explicit customer approval and console recovery.
- [ ] Confirm dashboard bind/authentication, operator roles, secrets handling, and network exposure; use verified TLS for remote access.
- [ ] Document pilot owner, scope, maintenance window, escalation contacts, and rollback procedure.

## Release / marketing guardrails

- Do not describe Sentinel as certified, vulnerability-free, or production-ready based only on automated tests.
- A passing queue test does not establish third-party message receipt.
- A dry-run firewall test does not establish that live rules are safe on a customer's host.
- The security-hardening milestone and documentation update do not create a release tag, publish a package, authorize deployment, or approve production use.
- Keep Sentinel classified as a **pilot candidate** until the four remaining security items and operational validation are complete and independently verified.

**Owner sign-off / date:** __________________
