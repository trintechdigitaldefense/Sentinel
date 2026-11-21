# SENTINEL Security & Operational Readiness Audit — historical snapshot plus current-main revalidation

**Original audit date:** 2026-11-17  
**Current-main revalidation:** 2026-11-21  
**Current application/security source baseline:** `d8bd2caeb39f62d17972891a0f8dd8d4c7a3de50` (PR #35 merge; includes PR #31 agent transport and PR #34 firewall changes)  
**Current dependency/CI baseline:** `9b105dc32a41a2342a2440dc18b1122c4cdf5672` (PR #27 merge; dependency and workflow changes only)  
**Original reviewed baseline:** `main` at `a9fac56fef73c7344bb4af92a6053124b7894caa` (PR #10 merge); this remains the baseline for the historical findings below.  
**Review branch:** `security/readiness-audit-2026-11`  
**Scope:** Static source and test review of dashboard security, installer safety, alert delivery/queue reliability, and firewall validation readiness.  
**Execution limits:** Repository source and test files were inspected through GitHub. No repository checkout was executed in an isolated local runtime during this review. No live dashboard, recipient, firewall, host-restart, or customer test was run. Findings below are source/test-evidence findings, not claims of successful exploit reproduction.

## Executive assessment

The 2026-11-17 findings below are a historical snapshot of baseline `a9fac56`. They must not be read as current-main findings without the revalidation section near the end of this document. Sentinel remains **not cleared for unrestricted production deployment or an unsupervised customer pilot**. The 2026-11-21 source/test revalidation found that several historical code findings have since been addressed on current `main`; however, operational verification, external independent review, and other residual gates remain open.

The current-main revalidation was a read-only GitHub source and test inspection. No local test suite was executed by this reviewer, no reverse proxy/certificate or live recipient was exercised, no firewall rules were applied, and no host restart/power-loss drill was run. Test files and CI records are evidence to inspect, not a claim that those tests were executed during this revalidation.

## Findings

### SNT-DA-01 — Viewer token can promote viewer role to administrator
**Severity:** High  
**Area:** Dashboard authorization  
**Evidence:** `modules/dashboard_impl.py`, `_Handler.do_POST`, control-mode branch. When the requested state is ON and `dashboard.allow_control` is already true, the handler writes `dash["role"] = "admin"`. It authenticates using the same dashboard token accepted by `_auth_ok()`; it does not verify an administrator password or separate control credential. `modules/rbac.py::can_control` requires both `allow_control` and role `admin`.  
**Test gap:** `tests/test_dashboard_authz.py` and `tests/test_dashboard_authz_priority2.py` test denial when config has `allow_control=false`, and disabling controls. They do not test `allow_control=true, role=viewer` with the viewer token.  
**Impact:** A holder of the shareable dashboard token can elevate a configured viewer to the role that enables control actions, where an operator has previously enabled control mode.  
**Remediation:** Remove role mutation from the token-authenticated endpoint. Require a separate administrator re-authentication or locally provisioned control credential for privilege changes. Keep role and allow-control decisions server-side; make the ordinary share token read-only. Add a regression test for the exact true/viewer state and assert role remains viewer and privileged actions remain denied.  
**Residual risk:** Until fixed, do not distribute the dashboard token to viewers or expose the dashboard beyond a trusted local management boundary.

### SNT-DA-02 — Live threat refresh inserts untrusted fields through innerHTML
**Severity:** High  
**Area:** Dashboard browser security / XSS  
**Evidence:** `modules/dashboard_impl.py`, JavaScript `renderThreats(rt)`. Values from `rt.threats` including `severity`, `type`, and `cmd/detail/id/port` are concatenated into an HTML string and assigned to `tbodyHint.innerHTML`. These fields originate from host/process/threat telemetry and must be treated as untrusted text. The initial server-rendered threat rows use an `esc()` helper, but the polling path does not apply equivalent escaping.  
**Test gap:** Current dashboard authorization tests do not exercise hostile threat values in the browser or verify safe DOM rendering.  
**Impact:** If attacker-influenced telemetry reaches these fields, a dashboard viewer's browser may interpret it as markup/script rather than text.  
**Remediation:** Construct rows with DOM APIs (`createElement`, `textContent`, and validated class names) instead of HTML concatenation. If string templating is retained, context-appropriate escaping must cover text and attribute contexts, but DOM construction is preferred. Add tests using HTML/script-like values and a browser-level assertion that they render as text and do not execute.  
**Residual risk:** Static inspection establishes an unsafe sink, not a complete end-to-end exploit path from a remote attacker to each telemetry source. Treat as high priority regardless.

### SNT-DA-03 — Dashboard token remains accepted in query strings and embedded in links
**Severity:** Medium  
**Area:** Authentication / token handling  
**Evidence:** `modules/dashboard_impl.py::_Handler._auth_ok` accepts `?token=` after Bearer and cookie checks. `_html()` embeds the token in report, logo, and other resource URLs; the response sets `sentinel_token` as HttpOnly and SameSite=Strict but omits Secure.  
**Impact:** Query tokens can be copied into browser history, proxy/access logs, screenshots, and other URL-handling surfaces. Cookie transport is not explicitly restricted to HTTPS.  
**Remediation:** Replace URL-token navigation with a short-lived authenticated session established by a POST or equivalent protected exchange; use Bearer headers for API calls and an HttpOnly, Secure, SameSite cookie for browser sessions when HTTPS is in use. Redact credentials from logs and avoid putting tokens in HTML URLs. If HTTP loopback operation remains supported, document its boundary and do not claim Secure-cookie protection on plaintext HTTP.  
**Test gap:** Existing tests explicitly confirm Bearer and cookie support but do not assert that query-string authentication is rejected or that tokens are absent from rendered HTML.

### SNT-IN-01 — Invalid existing config can be overwritten with defaults during setup
**Severity:** High  
**Area:** Installer / customer data preservation  
**Evidence:** `setup.py::init_config` attempts to parse an existing `config.json`. On any parse/read exception it logs that the config is unreadable and writes `default_config()` to the same path. This can replace a malformed but recoverable customer configuration, including alert endpoints and credentials, without first preserving the original file.  
**Remediation:** Never overwrite an existing unreadable config automatically. Fail closed with a clear recovery message, preserve the original bytes, and create a timestamped restricted-permission backup before any operator-approved repair. Add tests asserting byte-for-byte preservation for malformed JSON, permission/read errors, and partial config migration.  
**Residual risk:** This finding concerns setup execution after repository synchronization; the default Git fast-forward path does not itself delete the external `SENTINEL_DIR`.

### SNT-IN-02 — Installer safety tests do not execute the actual upgrade script end-to-end
**Severity:** Medium  
**Area:** Installer validation  
**Evidence:** `tests/test_install_safe.py` primarily inspects script text. `tests/test_install_upgrade_scenarios.py` creates temporary Git repositories, but its dirty-file test explicitly describes itself as simulating the safe path and asserts source text rather than invoking `install.sh` against a controlled origin/checkout.  
**Impact:** The current tests provide useful guardrails but do not prove that branch switching, failed fast-forward, untracked files, dirty tracked files, or local commits behave safely when the installer actually runs.  
**Remediation:** Add end-to-end shell tests using temporary bare origin and working repositories, a fake `python3` shim or isolated setup stub, and explicit assertions on tracked/untracked content and HEAD before/after. Cover clean fast-forward, dirty conflicting file, untracked file, local-only commit/divergence, missing local branch, and explicit recovery flag in a disposable fixture only. Never point these tests at the real working checkout.

### SNT-AL-01 — Offline queue silently discards oldest entries after 500
**Severity:** High  
**Area:** Alert reliability / queue retention  
**Evidence:** `modules/phase4.py::offline_enqueue` reads the current queue, appends a row, then applies `lines = lines[-500:]` before atomic write. If the queue already contains 500 unconfirmed entries, appending a new alert silently removes the oldest entry.  
**Impact:** During a prolonged outage or high-volume alert storm, undelivered alerts can be discarded without an explicit overflow result or durable overflow record. This conflicts with the queue's otherwise careful confirmed-delivery retention behavior.  
**Remediation:** Do not silently evict unconfirmed alerts. Prefer a bounded queue that rejects new enqueue with an explicit error while preserving all existing rows, or implement a documented spill/archive policy with atomic writes, permissions, and operator-visible capacity alerts. Add tests at 499, 500, and 501 entries and verify no unconfirmed entry disappears.  
**Residual risk:** Existing tests cover failed delivery, exceptions, malformed rows, no sender, retry, and concurrent append preservation, but do not cover capacity overflow.

### SNT-AL-02 — Delivery confirmation is transport-level, not proof of recipient receipt
**Severity:** Medium  
**Area:** Alert delivery assurance  
**Evidence:** `modules/alerting.py` marks a channel sent based on successful local API/SMTP call completion; the offline queue removes rows only when the sender returns explicit `sent=True` or `delivered=True`. Syslog uses UDP `sendto`, which cannot establish receiver receipt. SMTP acceptance likewise does not establish inbox delivery or human acknowledgement.  
**Impact:** The application can report successful handoff while downstream delivery, filtering, or recipient visibility remains unknown.  
**Remediation:** Use precise statuses such as `accepted_by_transport`, `delivered` (only where provider receipts support it), and `acknowledged`. Keep the current queue semantics tied to a clearly documented acceptance contract; avoid marketing claims of confirmed receipt. Provide an operator test workflow using an explicitly approved test recipient or endpoint.  
**Residual risk:** Real channel receipt and downstream processing remain unverified in this audit.

### SNT-AL-03 — Queue implementation has strong basic failure-retention coverage, but restart/power-loss validation is absent
**Severity:** Medium  
**Area:** Alert queue recovery  
**Evidence:** `modules/phase4.py` uses file locks, atomic replacement, fsync, and reconciliation to preserve concurrent additions. Tests cover no sender, confirmed/unconfirmed delivery, sender exceptions, malformed rows, and entries added during flush. `tests/test_queued_alert_delivery.py` covers failed initial delivery followed by retry and successful queued delivery.  
**Gap:** No reviewed test demonstrates recovery across an actual process termination or host restart while a flush is in progress, nor storage-full/permission failure behavior.  
**Remediation:** Add subprocess kill/restart tests around enqueue, queue snapshot, send, and reconciliation boundaries. Test disk-full/permission failures with fault injection. For field validation, use a disposable VM and a non-production test endpoint; record queue count and checksums before and after restart.  
**Residual risk:** Atomic-file patterns reduce risk but do not by themselves prove host/power-loss behavior on every supported filesystem.

### SNT-FW-01 — Firewall dry-run tests do not validate live ruleset safety or rollback
**Severity:** Medium  
**Area:** Firewall operational validation  
**Evidence:** `tests/test_firewall.py` covers dry-run block/profile behavior, refusal of loopback and `/0`, and managed-block planning. `tests/test_firewall_dry_run_contract.py` checks dry-run contract at a broad level. The release checklist itself records live apply on a disposable VM as outstanding.  
**Remediation:** Keep the default validation read-only. First capture backend, current ruleset, operator IPs, route/SSH state, and a rollback plan. Apply only in a disposable VM with console access and a pre-scheduled rollback. Verify expected rules and connectivity from a second session, then test rollback. Never run these procedures against a customer host without explicit approval and an agreed maintenance window.  
**Residual risk:** No live firewall apply was performed or authorized during this audit. Dry-run tests do not establish safe live behavior.

## Controlled validation procedures (not executed)

### Dashboard
1. Run the dashboard bound to loopback only in an isolated test environment with synthetic config and data.
2. Verify missing/invalid credentials receive 401 for every protected route.
3. Verify viewer role cannot enable controls, ACK alerts, or invoke mutating actions even when control mode is enabled in config.
4. Supply synthetic threat fields containing HTML/script-like strings; verify they display literally and do not execute.
5. Verify no token appears in generated links, browser-visible query strings, referrers, or logs; test response headers and cookie attributes over the intended TLS deployment.

### Installer
1. Create a temporary bare Git origin and temporary checkout containing a Sentinel-like fixture; do not use the operator's actual checkout.
2. Exercise clean fast-forward, dirty tracked file, untracked file, local-only commit, diverged branch, missing branch, and recovery mode.
3. Assert default mode never changes or removes uncommitted tracked/untracked content and never invokes `reset --hard` or `clean`.
4. Use a temporary `SENTINEL_DIR`; test valid config migration, malformed config preservation, permissions, and backup behavior.
5. Confirm setup scripts report failed migration/wiring steps as failures rather than silently claiming setup completion.

### Alert delivery and queue
1. Use mocked SMTP/webhook transports and synthetic alerts only; no real recipients.
2. Simulate timeout, HTTP error, SMTP refusal, sender exception, ambiguous post-acceptance disconnect, and queue-write failure.
3. Verify failed/unconfirmed rows remain; only explicitly confirmed rows are removed; concurrent enqueues survive flush.
4. Test capacity boundaries and subprocess termination/restart using a temporary data directory.
5. Separately, if owner-approved later, use a designated test endpoint/recipient and document transport acceptance versus actual receipt.

### Firewall
1. Start with status and dry-run only; preserve command output and current ruleset snapshot.
2. Validate refusal of loopback, unspecified, multicast, and broad networks; verify operator-IP protection and IPv4/IPv6 planning.
3. On a disposable VM only, ensure out-of-band console access and a timed rollback before any apply.
4. Apply the smallest test rule, verify from a second session, then execute rollback and verify restoration.
5. Do not run live firewall changes on customer hosts as part of this audit.

## Positive evidence already present

- The owner reported `python3 -m pytest -q` on synchronized `main`: **242 passed, 1 ReportLab deprecation warning**; `git diff --check` was clean.
- PR #10 post-merge CI was reported passing.
- Alert tests cover concurrency, retry bypassing dedup, failed delivery retention, malformed queue rows, and concurrent queue additions.
- Installer uses fast-forward-only upgrade by default and gates hard reset behind `SENTINEL_RECOVER_SYNC=1`; however, end-to-end behavior still needs stronger tests.
- Firewall tests establish dry-run defaults and several target-validation guards.

## Remediation order

1. Fix SNT-DA-01 and SNT-DA-02 first; add focused regression tests and browser-safe rendering.
2. Fix SNT-IN-01 and add real temporary-Git installer integration tests for SNT-IN-02.
3. Fix SNT-AL-01 before relying on offline queue retention during extended outages.
4. Add process-restart and capacity tests; document transport acceptance semantics.
5. Complete firewall disposable-VM validation only with explicit owner approval.
6. Re-run full CI and local test suite; obtain independent review of each remediation PR.

## Current-main revalidation — 2026-11-21

**Application/security source baseline inspected:** `c9561a0c3d8bc42cd6b8b0670fe4aae0ac9d8c44`. Dependency and CI metadata were refreshed separately by PR #27.  
**Method:** read-only inspection of current source, test files, release checklist, and PR #8/#11 metadata. No code execution or live operational testing was performed in this revalidation.

### Historical finding disposition on current main

| Historical finding | Current-main observation | Revalidation status |
|---|---|---|
| SNT-DA-01 — viewer token can promote viewer to administrator | Current `/api/control-mode` logic requires both locally provisioned `allow_control=true` and `role=admin`; it does not promote a viewer. `tests/test_dashboard_authz_priority2.py` includes a viewer-token regression test. | **Addressed in source/test coverage; independent review still required.** |
| SNT-DA-02 — live threat refresh uses unsafe `innerHTML` | Current `renderThreats` creates DOM elements and assigns telemetry with `textContent`. Browser-security tests exercise HTML-like payloads. | **Addressed in source/test coverage; independent browser review still required.** |
| SNT-DA-03 — query-string dashboard token and token-bearing links | Current `_auth_ok` accepts Bearer headers and session cookies only; tests assert query-string authentication fails and rendered HTML does not embed the access token. Sign-in submits the token by POST and sets a session cookie. | **Addressed in source/test coverage.** Secure cookie remains explicitly enabled only for configured HTTPS/reverse-proxy mode; this is intentional for loopback HTTP. |
| SNT-IN-01 — setup overwrites invalid config | Current `setup.py::init_config` refuses symlinks, malformed/unreadable config and failed updates; it uses an atomic writer. `tests/test_setup_safe_config.py` covers invalid-config preservation. | **Addressed in source/test coverage; filesystem edge cases still merit independent verification.** |
| SNT-IN-02 — installer tests do not execute the upgrade script end-to-end | Current `tests/test_install_upgrade_e2e.py` executes `install.sh` against an isolated local Git fixture and covers fast-forward, dirty-file, untracked-file and local-divergence cases. | **Partially addressed.** Review remaining branch/recovery/error paths and confirm no test targets a real operator checkout. |
| SNT-AL-01 — offline queue silently evicts oldest entries at 500 | Current `offline_enqueue` rejects a new item at capacity and preserves existing rows. `tests/test_offline_queue.py` covers 499/500 boundaries and preservation. | **Addressed in source/test coverage.** |
| SNT-AL-02 — transport acceptance is not recipient receipt | SMTP/API handoff and UDP syslog cannot establish human receipt or acknowledgement. No end-to-end recipient receipt proof was inspected. | **Open limitation.** Keep delivery language precise and test only with an approved recipient/endpoint. |
| SNT-AL-03 — restart/power-loss recovery is not proven | Current queue tests cover failure retention, retries, malformed entries and concurrent additions. No current-main test proving process-kill, host-restart, power-loss or storage-failure recovery was identified in the reviewed test inventory. | **Open.** Requires controlled isolated recovery drills. |
| SNT-FW-01 — live firewall apply/rollback was not validated | PR #34 adds transactional nftables apply/verify/restore, validates operator IPs and deny-port inputs, and reports partial defense-pack failures. Its isolated `firewall-live-isolated` and `ssh-lockout-live` CI jobs both passed. | **Addressed in current-main source and isolated CI.** A customer-specific change/rollback drill remains required before enabling firewall changes on a client host. |


### SNT-IN-03 — setup mutates application source during normal setup

**Severity:** Medium  
**Area:** Installer integrity / reproducibility  
**Evidence:** Current `setup.py::main()` calls `apply_cases_wire()` and `apply_dashboard_cases()` during a normal setup run. Those functions execute repository scripts (`scripts/apply_cases_wire.py` and `scripts/apply_dashboard_cases.py`) that wire features by editing application source files. This means setup can modify the checkout rather than limiting itself to dependency checks and configuration initialization. The `--check` path returns before those calls, but `check_engine()` uses `py_compile.compile()` and can create bytecode cache files despite the usage text describing check-only mode as no-write.  
**Impact:** A setup run may produce untracked/modified source files, make the deployed checkout differ from the reviewed commit, and complicate integrity checks or upgrades.  
**Remediation:** Remove runtime source rewriting from setup; ship wired application code as reviewed source. Make setup fail clearly if a required wiring step is missing rather than editing source at install time. Ensure check-only mode performs no filesystem writes, including bytecode caches. PR #36 removes the runtime source-wiring calls and deletes the obsolete scripts.  
**Revalidation status:** **Addressed in PR #36 source changes and regression tests.** Setup no longer executes either source-wiring script; the scripts are removed. Independent verification on a disposable install remains advisable.

### Issues #15–#18 acceptance status

| Issue | Current evidence inspected | Remaining acceptance |
|---|---|---|
| [#15 — Origin/Host and CSRF](https://github.com/trintechdigitaldefense/Sentinel/issues/15) | Current origin/host validator; cookie-authenticated POST checks; tests for same-origin, mismatched, missing/null/malformed/duplicate headers; browser regression coverage. | Independent reviewer must verify all state-changing routes and demonstrate rejected requests do not mutate state. |
| [#16 — atomic runtime config writes](https://github.com/trintechdigitaldefense/Sentinel/issues/16) | Same-directory temporary file, restrictive mode, fsync/replace and cleanup; tests for replace failure, malformed config, symlink, dangling symlink and FIFO. | Independent reviewer must verify failure preservation, permission behavior, and concurrent-update behavior on supported hosts. |
| [#17 — remote dashboard TLS](https://github.com/trintechdigitaldefense/Sentinel/issues/17) | Loopback-only backend guard; remote-access config requires secure cookie and explicit trusted hosts; deployment guide contains reverse-proxy verification checklist. | Actual target-host certificate, HTTPS-only access, proxy trust/Host behavior, Secure cookie, port exposure and rollback must be checked. Source/config tests are not live TLS evidence. |
| [#18 — CSP hardening](https://github.com/trintechdigitaldefense/Sentinel/issues/18) | Current CSP uses nonces and disallows inline script/style attributes; browser test asserts no `unsafe-inline`, no inline event handlers and safe telemetry/report rendering. | Independent browser/security review must verify the complete supported workflow and representative injection cases under supported browsers. |

**Independence note:** The GitHub review record inspected for PR #8 is a COMMENT authored by the repository owner account, not an approval by an independent maintainer. PR #11 has no submitted reviews. No independent reviewer approval for issues #15–#18 was found in the repository records inspected. This revalidation therefore does **not** satisfy the independent-review acceptance criteria.

### Additional current-main finding: central agent transport

PR #31 now applies TLS to non-loopback central-agent listeners and fails closed when certificate/key configuration is missing or invalid. Network listeners reject the legacy shared-token mode and require per-agent credentials; the reporting client requires HTTPS off-loopback and validates the configured CA. Automated SSH enrollment now requires a preverified known-hosts entry. This addresses the source-level transport finding, but certificate provisioning, key rotation/revocation procedures, systemd service behavior and a real target-host deployment still require operational verification. This is separate from dashboard TLS issue #17.

### Current disposition

- Keep issues #15–#18 **OPEN** until the independent review and operational acceptance evidence specified in each issue is recorded.
- Keep Sentinel classified as a **pilot candidate**. PR #31 provides TLS-enforced, per-agent-authenticated central transport in source, but target-host certificate provisioning and service operation still need validation. Do not claim production certification or 24/7 staffed response.
- Treat PR #34 isolated live nftables and SSH-continuity CI as current-main regression evidence, not customer-host certification. PR #40 adds a dedicated `agent-systemd-live` job; its disposable Ubuntu/systemd container test passed service installation, start, restart, stop and start. This is CI evidence, not target-host service certification.
- Re-run full CI on the exact current main SHA and record the workflow result. The current-main status lookup for the application/source baseline `d8bd2caeb39f62d17972891a0f8dd8d4c7a3de50` returned no post-merge workflow result; PR-head CI is recorded separately in the relevant pull requests.
- Complete controlled process-restart/storage-failure drills and a customer-specific firewall change/rollback plan only under a separately approved test plan.

## Final disposition

**Status: NOT CLEARED for unrestricted production or unsupervised customer pilot (revalidated against current main on 2026-11-21).**  
**Suitable next stage:** isolated remediation and controlled evaluation, with no customer production changes.  
**Not performed:** live customer testing, real recipient delivery, customer-host firewall apply, deployment, release, or package publication.

This audit records source-level findings and test gaps as of the reviewed baseline. It is not a penetration test, certification, or guarantee that no other vulnerabilities exist.
