# SENTINEL release checklist

**Current reviewed change:** PR #19 merged to `main` on 2026-11-18  
**Merge commit:** `bc40fe6d5012c061fbdab13544ba3cbf5078dc1d`  
**Product status:** **pilot candidate**. This checklist does not declare a production release, certification, or deployment approval.

Legend: **PASS** = evidence recorded · **PARTIAL** = automated/static evidence only · **OPEN** = required evidence or owner decision remains.

## Security-hardening milestone — PR #19

PR #19 implements the four dashboard/deployment hardening work items:

| Item | Merged implementation | Remaining acceptance evidence |
|---|---|---|
| #15 — CSRF Origin/Host validation | Same-origin and Host validation for cookie-authenticated POST requests; rejects invalid origins before reading request bodies. | Independent review confirmation should be recorded in GitHub; controlled host/browser checks must show same-origin success and cross-origin/Host mismatch rejection without state mutation. |
| #16 — atomic runtime configuration writes | Same-directory temporary file, restrictive mode, fsync/replace, guarded reads and rejection of symlink/special-file paths. | Controlled host checks for ownership, permissions, failure preservation and concurrent update behavior. |
| #17 — remote dashboard TLS | Backend forced to literal `127.0.0.1`; remote access requires explicit `remote_access=true` and `cookie_secure=true`; TLS reverse-proxy guide added. | **OPEN:** actual proxy, certificate, TLS protocol, Host handling, cookie attributes, port exposure and rollback must be verified on the target host. |
| #18 — CSP hardening | Nonce-based script/style blocks; inline event/style attributes removed from active template; `unsafe-inline` removed from script/style policy. | Independent review record and supported-browser regression verification on the deployed build. |

PR-head GitHub Actions run **44149308038** passed on Python 3.10 and 3.12, with Ruff, Python compilation, firewall dry-run smoke and **295 pytest tests** on each version. This is PR-head CI evidence; it is **not** a post-merge run on merge commit `bc40fe6`. The GitHub connector currently reports no combined status checks for the merge commit. Do not mark post-merge CI as passed until a successful run is visible on the resulting `main` revision.

The owner reports that an independent reviewer approved PR #19. The available PR review API did not return a submitted review, so retain the reviewer’s approval as owner-reported until it is recorded or otherwise independently evidenced.

## Current release gates

| Gate | Status | Evidence / remaining work |
|---|---|---|
| PR #19 merged | **PASS** | Merge commit `bc40fe6d5012c061fbdab13544ba3cbf5078dc1d`. |
| PR-head regression CI | **PASS** | Run 44149308038; 295 tests passed on Python 3.10 and 3.12. |
| Post-merge CI on resulting main | **OPEN** | No run/status evidence currently visible for the merge commit. |
| CSRF implementation | **PASS** (PR-head automated) | New tests cover same-origin, cross-origin, Host mismatch, missing/null/malformed Origin, HTTPS proxy scheme, Bearer requests and rejection before body processing. |
| Runtime config atomicity | **PASS** (PR-head automated) | Tests cover permissions, replace failure, symlinks, dangling symlinks, FIFO, malformed JSON, preservation and temp cleanup. |
| Dashboard loopback/TLS guard | **PARTIAL** | Automated config/bind tests and deployment guide exist; real reverse proxy/certificate is not configured or verified. |
| CSP hardening | **PASS** (PR-head automated) | Browser security tests assert nonce-bearing script/style tags, no inline handlers and no `unsafe-inline`. Target-browser operational check remains. |
| Independent security review | **PARTIAL** | Owner reports approval; approval is not currently visible as a GitHub review submission. |
| Firewall dry-run behavior | **PARTIAL** | Automated smoke/contract tests; no live apply validation on a disposable VM is recorded. |
| Live alert channel delivery and receipt | **OPEN** | No real recipient, WhatsApp, webhook, syslog or SIEM delivery test is claimed. Requires separately approved test endpoint/recipient. |
| Offline queue across real host restart / power loss | **PARTIAL** | Automated persistence/queue tests exist; field restart/soak evidence remains. |
| Detection coverage and false-positive rate | **OPEN** | Requires representative pilot telemetry and operator review. |
| Current security audit / residual-risk review | **OPEN** | Historical `SECURITY_AUDIT.md` is not a fresh audit of merged main. Revalidate findings against current code. |
| Secrets and deployment configuration review | **OPEN** | Recheck target-specific secrets, credentials, network exposure and access controls before each pilot. |
| Install, upgrade, backup and rollback rehearsal | **OPEN** | Validate on a disposable supported host; preserve existing `~/.sentinel` data and trusted persistence baselines. |
| Operational owner sign-off | **OPEN** | Record approved pilot scope, maintenance window, escalation contacts, evidence and rollback owner. |

## Controlled operational validation plan

Perform these checks only on an isolated, disposable test host or a specifically approved pilot host. Do not alter a customer network or production configuration as part of repository validation.

1. **Baseline and backup:** record OS/Python versions, current commit, configuration permissions, service state, listening sockets and disk space. Back up only the required config and test fixtures; do not overwrite or reset `~/.sentinel`.
2. **Install/upgrade:** test clean installation and fast-forward upgrade from a representative supported version. Confirm user data and configuration are preserved. Rehearse rollback.
3. **Dashboard local boundary:** verify the service listens only on `127.0.0.1`; confirm it is not reachable from another host. Verify default viewer role and token/session behavior.
4. **CSRF:** verify same-origin cookie-authenticated POST works; cross-origin, missing/null/malformed Origin and Host mismatch are rejected before state changes. Verify valid Bearer API behavior remains as designed.
5. **Runtime configuration:** verify resulting config is a regular file with mode `0600`; induce a safe write/replace failure in a disposable fixture and confirm the prior valid config remains intact.
6. **TLS proxy (only if remote access is explicitly in scope):** verify same-host proxy, valid hostname certificate, TLS 1.2/1.3, HTTP redirect/rejection, unknown Host rejection, loopback-only backend, Secure/HttpOnly/SameSite=Strict cookie, and no secrets in proxy logs. Confirm certificate renewal and rollback ownership.
7. **CSP/browser:** exercise login, dashboard controls, reports, telemetry and error states in supported browsers; inspect console/network errors and verify representative injected markup remains inert.
8. **Monitoring/alerts:** run a supervised hunt cycle and inspect logs, alert persistence and queue retry behavior. Use only a separately approved test recipient/endpoint for delivery tests.
9. **Firewall:** verify dry-run output first. Do not apply live firewall rules without separate explicit approval and console recovery access.
10. **Evidence and rollback:** capture sanitized command output, timestamps, versions and outcomes; redact tokens, credentials, client identifiers and private network details. Rehearse rollback and record owner sign-off.

## Required before production approval

- [ ] Post-merge CI passes on the exact current `main` commit.
- [ ] Independent reviewer approval is recorded and any review threads are resolved.
- [ ] Current security audit and residual risks are reviewed against merged code.
- [ ] Controlled install/upgrade, configuration preservation and rollback pass on a disposable supported host.
- [ ] Dashboard CSRF, config atomicity, loopback boundary and CSP/browser checks pass.
- [ ] If remote dashboard access is required, TLS proxy/certificate/Host/cookie/network checks pass; otherwise remote access remains disabled.
- [ ] Supervised hunt, alert persistence, approved alert delivery and queue recovery evidence are recorded.
- [ ] Firewall remains dry-run unless a separate live-change approval is given.
- [ ] Detection coverage and false-positive limitations are documented for the intended pilot scope.
- [ ] Secrets, access control, owner, escalation and rollback plan are reviewed.
- [ ] Owner signs off on the specific deployment scope and accepts residual risk.

## Release / marketing guardrails

- Do not describe Sentinel as certified, vulnerability-free or production-ready based only on automated tests.
- PR-head CI is not post-merge CI; post-merge CI is not field validation.
- A passing queue test does not establish third-party message receipt.
- A dry-run firewall test does not establish that live rules are safe on a customer's host.
- The TLS guide and `cookie_secure=true` setting do not prove that a reverse proxy or certificate is correctly deployed.
- Do not publish a production release or change Sentinel's status until all required gates are evidenced and owner-approved.

**Owner sign-off / date:** __________________
