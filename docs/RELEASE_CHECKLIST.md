# SENTINEL release checklist

**Current reviewed revision:** `e80c09b5a1cc461ed7d598cea9c1c5b2ec0c58ae` (`main`, PR #9 merged)  
**Updated:** 2026-11-17  
**Product status:** pilot candidate; no production release or certification is declared by this checklist.

Legend: **PASS** = current evidence recorded · **PARTIAL** = automated/static evidence only · **OPEN** = evidence or owner decision still required.

| Gate | Status | Current evidence / remaining work |
|---|---|---|
| PR #9 alert reliability merged | **PASS** | Merge commit `e80c09b5a1cc461ed7d598cea9c1c5b2ec0c58ae` on `main` |
| PR #9 CI | **PASS** | GitHub Actions Python 3.10 and 3.12 jobs passed before merge |
| Post-merge local regression suite | **PASS** | Python 3.12: `python3 -m pytest -q` → 242 passed, 1 ReportLab deprecation warning |
| Active finding state and delivery retry | **PASS** (automated) | Regression tests cover lifecycle, failure/retry, concurrency, queue retention, and compatibility |
| Installer preserves local data by default | **PASS** (automated/static) | Installer safety implementation and regression tests; still test upgrades on supported target platforms |
| Dashboard authorization | **PARTIAL** | Authorization tests pass; full browser/XSS and exposed-network assessment remain open |
| Firewall dry-run behavior | **PARTIAL** | Dry-run/contract tests exist; no live apply validation on a disposable VM is recorded here |
| Live alert channel delivery and receipt | **OPEN** | No real recipient, WhatsApp, webhook, syslog, or SIEM delivery test is claimed |
| Offline queue across real host restart / power loss | **PARTIAL** | Automated persistence/queue tests exist; field restart/soak evidence is still needed |
| Detection coverage and false-positive rate | **OPEN** | Requires representative pilot telemetry and operator review |
| Current security audit / residual-risk review | **PARTIAL** | `SECURITY_AUDIT.md` is a historical audit snapshot; perform a fresh review against current `main` |
| Secrets and deployment configuration review | **OPEN** | Recheck target-specific secrets, credentials, network exposure, and access controls before each pilot |
| Owner sign-off and rollback rehearsal | **OPEN** | Owner must review residual risks, approve the pilot scope, and rehearse rollback |

## Required before a customer pilot

- [ ] Review the current code and historical findings in [SECURITY_AUDIT.md](SECURITY_AUDIT.md); record disposition of each remaining risk.
- [ ] Validate install, upgrade, backup, and rollback on a disposable supported host.
- [ ] Run `doctor`, confirm intended baselines/canaries, and observe a supervised hunt cycle.
- [ ] Verify alert routing with an explicitly approved test endpoint/recipient; record delivery and queue retry evidence.
- [ ] Validate firewall behavior in dry-run first; live apply only with explicit customer approval and console recovery.
- [ ] Confirm dashboard bind/authentication, operator roles, secrets handling, and network exposure.
- [ ] Document pilot owner, scope, maintenance window, escalation contacts, and rollback procedure.

## Release / marketing guardrails

- Do not describe Sentinel as certified, vulnerability-free, or production-ready based only on automated tests.
- A passing queue test does not establish third-party message receipt.
- A dry-run firewall test does not establish that live rules are safe on a customer's host.
- The PR #9 merge and documentation refresh do not create a release tag, publish a package, or authorize deployment.

**Owner sign-off / date:** __________________
