# SENTINEL release checklist

**Historical checklist baseline:** 2026-11-17 (PRs #14, #13, and #12 merged). The entries below preserve the evidence recorded at that time; the 2026-11-20 addendum at the top is the latest status update and supersedes older branch-head/test-count snapshots where they differ.  
**Product status:** **pilot candidate**; no production release, certification, or deployment approval is declared by this checklist.

## Latest status addendum — 2026-11-20

**Operating model:** Sentinel is a **supervised automated monitoring tool**. Continuous monitoring may run on a supported always-on host, but alert triage, finding validation, escalation, and response decisions remain under an authorised human operator. Service uptime is not a promise of staffed 24/7 response. This is the intended product model, not an unresolved autonomy defect.

**PR #21 — dashboard PDF-serving hardening: MERGED**
- Target: `main`; merge commit: `d639b9d8beb17c64ad4904af281f81096feff4fe`.
- Hardened approved PDF reads against filename traversal, unsafe response-header filenames, symlinked PDF files, symlinked `data` / `reports` directories, non-regular files, and generated-report paths outside the approved reports directory.
- Added regression tests for symlinked directory components and generated-report paths.
- Validation on the PR commit: full local suite **310 passed, 1 skipped**; Ruff critical checks and Python compilation passed; GitHub Actions passed on Python 3.10 and 3.12.
- Scope limitation: this verifies the PDF-serving change and automated regression behavior. It is not a live remote-dashboard penetration test, independent audit, production certification, or customer-host validation.

**Open dashboard/deployment security work**
| Issue | Priority | Status | Next action |
|---|---|---|---|
| [#15 — Origin/Host validation for state-changing requests](https://github.com/trintechdigitaldefense/Sentinel/issues/15) | High | **OPEN** | Implement CSRF checks and prove rejected cross-origin requests do not mutate state |
| [#16 — atomic runtime configuration writes](https://github.com/trintechdigitaldefense/Sentinel/issues/16) | High | **OPEN** | Preserve existing valid config across symlink, special-file, and write/replace failures |
| [#17 — remote dashboard TLS requirements](https://github.com/trintechdigitaldefense/Sentinel/issues/17) | High | **OPEN** | Define trusted-proxy/TLS setup and verify secure cookies; remote dashboard access remains unapproved |
| [#18 — CSP hardening](https://github.com/trintechdigitaldefense/Sentinel/issues/18) | Medium | **OPEN** | Reduce `unsafe-inline` and add browser regression tests |

**Next engineering priority:** Issue #15, because it protects state-changing dashboard routes against cross-origin browser requests. Issues #16–#18 remain required security work and must not be treated as closed by PR #21.

**Current gate interpretation**
- PDF serving hardening: **PASS — automated regression evidence on PR #21**.
- Dashboard CSRF, atomic runtime config writes, remote TLS, and CSP: **OPEN**.
- Live firewall apply, real third-party alert delivery/receipt, restart/soak behavior, detection coverage/false-positive rate, independent review, and operational pilot sign-off: **OPEN or PARTIAL** as described below.
- Product status remains **pilot candidate**. No release tag, customer deployment approval, or production certification is created by PR #21 or this documentation update.

Legend: **PASS** = current evidence recorded · **PARTIAL** = automated/static evidence only · **OPEN** = evidence or owner decision still required.

## Historical security-hardening milestone — 2026-11-17

The 2026-11-17 milestone recorded merged changes to dashboard authentication/output handling, installer configuration safety, and offline alert-queue reliability. It was not a production-readiness declaration.

| Change | Record |
|---|---|
| PR #14 — offline queue overflow handling | Merged; rejects new queue entries at capacity rather than discarding older unconfirmed alerts. Merge commit: `7f20f544da56733da61824c8bdd7ffc9d08d8218`. |
| PR #13 — installer configuration preservation | Merged; adds guarded reads and atomic installer configuration writes with regression coverage. Merge commit: `91518fa75f877fb6b876add5260e4fd5771d5652`. |
| PR #12 — dashboard authentication and XSS hardening | Merged; improves viewer/admin separation, session handling, safe rendering, and security headers, with browser regression coverage. Merge commit: `933343c108d8e3d1cb42cfe9fc59378449896534`. |
| Combined-main regression suite | User-confirmed on the historical revision above: `python3 -m pytest -q` → **263 passed, 1 skipped, 1 warning in 72.81s**. This is historical evidence, not the PR #21 test count. |

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
| PR #21 PDF-serving hardening | **PASS** (automated) | Merge commit recorded above; 310 passed, 1 skipped locally and Python 3.10/3.12 CI passed on the PR commit. |
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
- [ ] Agree monitoring coverage, operator review cadence, alert acknowledgement targets, and escalation/response responsibilities with the pilot customer.

## Release / marketing guardrails

- Do not describe Sentinel as certified, vulnerability-free, or production-ready based only on automated tests.
- A passing queue test does not establish third-party message receipt.
- A dry-run firewall test does not establish that live rules are safe on a customer's host.
- Continuous monitoring capability does not imply a staffed 24/7 response service or autonomous incident decision-making.
- The security-hardening milestone and documentation update do not create a release tag, publish a package, authorize deployment, or approve production use.
- Keep Sentinel classified as a **pilot candidate** until the four remaining security items and operational validation are complete and independently verified.

**Owner sign-off / date:** __________________
