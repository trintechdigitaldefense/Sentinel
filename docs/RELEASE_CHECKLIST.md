# SENTINEL release checklist

**Application/security source baseline reviewed:** `3388e2bf1c88ac0b33b8cd6535c70a5abff3ba6d` (PR #35 merge, 2026-11-21)  
**Dependency/CI baseline:** `9b105dc32a41a2342a2440dc18b1122c4cdf5672` (PR #27 merge, 2026-11-21)  
**Product status:** **pilot candidate**. This checklist does not declare a production release, certification, or deployment approval.

## Latest repository status — 2026-11-21 (post-PR #24)

### Merged work

| Change | Status | Evidence / scope |
|---|---|---|
| PR #19 — dashboard/deployment hardening | **MERGED** | Implements cookie-authenticated Origin/Host checks, atomic runtime config updates, loopback-only backend binding and TLS configuration guards, and nonce-based CSP hardening. |
| PR #21 — PDF-serving hardening | **MERGED** | Rejects unsafe filenames, traversal, symlinked files/directories, non-regular files, and report paths outside approved locations. |
| PR #22 — supervised monitoring and readiness documentation | **MERGED** | Clarifies continuous monitoring versus human alert triage, escalation, and response responsibility. |
| PR #23 — dashboard Origin/Host validation follow-up | **MERGED** | Strengthens validation of cookie-authenticated state-changing requests and browser regression coverage. |
| PR #24 — repository documentation refresh | **MERGED** | Refreshes README, changelog, security policy, release checklist and historical audit labeling. |
| PR #25 — release baseline and agent transport documentation | **MERGED** | Updates the release baseline and documents the legacy HTTP agent transport limitation. |
| PR #26 — current-main audit revalidation | **MERGED** | Revalidates historical security findings, records issues #15–#18 acceptance status and documents additional setup/agent-transport risks. |
| PR #27 — dependency and GitHub Actions refresh | **MERGED** | Updates Requests, ReportLab, actions/checkout and actions/setup-python. |
| PR #31 — agent transport and per-agent credentials | **MERGED** | Enforces HTTPS/TLS for network listeners, per-agent credentials and strict SSH host-key verification. |
| PR #34 — firewall transaction safety | **MERGED** | Adds nftables validation, transactional restore, and isolated live nftables/SSH continuity CI. |
| PR #35 — case CLI and alert integration | **MERGED** | Tracks case auto-open and CLI wiring in source rather than relying on setup-time patching. |

### Automated evidence

- PR #27 CI passed on its PR head; no post-merge workflow result is claimed for its merge commit. PR #23 GitHub Actions passed on its PR head: **347 tests passed on Python 3.10 and 347 on Python 3.12**.
- PR #21 recorded **310 passed, 1 skipped** locally and passing Python 3.10/3.12 GitHub Actions on its PR commit.
- These are PR-head/historical test results. The current-main status lookup for `9b105dc32a41a2342a2440dc18b1122c4cdf5672` has returned no post-merge workflow result; therefore post-merge CI is **not claimed as verified** here.
- Passing automated tests do not establish live deployment safety, independent security approval, third-party message receipt, or production certification.

## Dashboard/deployment issues #15–#18

The implementation work has been merged through PR #19 and the Origin/Host follow-up in PR #23. The four tracking issues remain **OPEN** because their acceptance criteria require independent review and/or operational evidence. Do not close them solely because code has merged.

| Issue | Merged implementation | Remaining acceptance evidence |
|---|---|---|
| [#15 — Origin/Host validation](https://github.com/trintechdigitaldefense/Sentinel/issues/15) | PR #19 implementation, strengthened by PR #23. | Independent review of the current code and tests; verify same-origin success and rejected cross-origin/Host-mismatch requests do not mutate state. |
| [#16 — atomic runtime configuration writes](https://github.com/trintechdigitaldefense/Sentinel/issues/16) | PR #19 adds guarded atomic runtime configuration writes and failure-preservation tests. | Independent review; verify permissions, symlink/special-file rejection, failure preservation, and safe concurrent-update behavior on supported hosts. |
| [#17 — remote dashboard TLS requirements](https://github.com/trintechdigitaldefense/Sentinel/issues/17) | PR #19 adds loopback-only backend restrictions, explicit secure-cookie/remote-access configuration guards, and deployment guidance. | Actual reverse proxy, certificate, TLS, Host allowlist, Secure-cookie, port exposure, and rollback checks on the intended target host. Remote access remains unapproved until verified. |
| [#18 — CSP hardening](https://github.com/trintechdigitaldefense/Sentinel/issues/18) | PR #19 adds nonce-based script/style handling and removes `unsafe-inline` from the active script/style policy. | Independent review and supported-browser verification of login, controls, reports, telemetry, error states, and representative injection attempts. |

## Remaining release gates

| Gate | Status | Evidence / next action |
|---|---|---|
| Current-main CI | **OPEN** | Obtain and record a successful workflow run on the exact current `main` SHA. PR-head CI is not a substitute. |
| Independent review of #15–#18 | **OPEN** | Record reviewer approval and resolve review comments; keep the issues open until their acceptance criteria are met. |
| Fresh security audit | **OPEN** | `docs/SECURITY_AUDIT.md` is a historical snapshot from 2026-10-26, not a fresh audit of current `main`. Revalidate findings against current code. |
| Remote dashboard TLS | **OPEN** | Verify only if remote access is in the approved pilot scope; otherwise retain loopback-only access. |
| Firewall live apply | **PARTIAL** | Dry-run/contract tests exist. Live application requires a disposable host, console recovery, and separate explicit approval. |
| Third-party alert delivery and receipt | **OPEN** | Use a separately approved test recipient/endpoint and record delivery plus queue behavior. |
| Restart, power-loss, and storage recovery | **PARTIAL** | Automated persistence tests exist; controlled host-level recovery drills remain separate. |
| Detection coverage and false-positive rate | **OPEN** | Collect representative pilot telemetry and document limitations and operator review. |
| Install/upgrade/backup/rollback | **OPEN** | Validate on a disposable supported host; preserve existing `~/.sentinel` configuration and data. |
| Secrets, access control, and network exposure | **OPEN** | Review per deployment; do not expose the dashboard directly to the network. |
| Operational owner sign-off | **OPEN** | Record pilot scope, maintenance window, escalation contacts, review cadence, rollback owner, and accepted residual risk. |

## Controlled validation boundaries

- Keep the dashboard bound to `127.0.0.1` unless a separately approved and verified TLS reverse-proxy design is in place.
- Keep firewall actions in dry-run unless the owner separately approves a live change and console recovery is available.
- Test alert delivery only against an explicitly approved recipient or endpoint.
- Do not run destructive recovery, remove user data, or overwrite an existing `~/.sentinel` directory as part of routine upgrades.
- Do not infer 24/7 staffed response from continuous monitoring. Sentinel's operating model is supervised automated monitoring with an authorised human operator responsible for triage and response decisions.

## Required before production approval

- [ ] Post-merge CI passes on the exact current `main` commit.
- [ ] Independent review of dashboard security changes is recorded; issues #15–#18 meet their acceptance criteria.
- [ ] Fresh security audit and residual-risk disposition are completed against current code.
- [ ] Install, upgrade, configuration preservation, backup, and rollback pass on a disposable supported host.
- [ ] Dashboard authentication, CSRF/Origin/Host checks, runtime config safety, loopback boundary, and CSP/browser behavior are verified.
- [ ] If remote dashboard access is required, TLS proxy/certificate/Host/cookie/network checks pass; otherwise remote access remains disabled.
- [ ] Supervised hunt, alert persistence, approved alert delivery, and queue recovery evidence are recorded.
- [ ] Firewall behavior is validated in dry-run; any live change receives separate explicit approval.
- [ ] Detection coverage and false-positive limitations are documented for the intended pilot scope.
- [ ] Secrets, access controls, owner, escalation, maintenance, and rollback plans are reviewed.
- [ ] Owner signs off on the specific deployment scope and accepts the residual risk.

## Release and marketing guardrails

- Do not describe Sentinel as certified, vulnerability-free, or production-ready based only on automated tests.
- PR-head CI is not post-merge CI; post-merge CI is not field validation.
- A passing queue test does not establish third-party message receipt.
- A dry-run firewall test does not establish that live rules are safe on a customer's host.
- A TLS guide and `cookie_secure=true` setting do not prove a reverse proxy or certificate is correctly deployed.
- Continuous monitoring does not imply a staffed 24/7 response service or autonomous incident decision-making.
- Keep Sentinel classified as a **pilot candidate** until all required evidence is recorded and owner-approved.

**Owner sign-off / date:** __________________
