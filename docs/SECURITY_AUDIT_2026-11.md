# SENTINEL Fresh Security & Operational Readiness Audit

**Audit date:** 2026-11-17  
**Reviewed baseline:** `main` at `a9fac56fef73c7344bb4af92a6053124b7894caa` (PR #10 merge)  
**Review branch:** `security/readiness-audit-2026-11`  
**Scope:** Static source and test review of dashboard security, installer safety, alert delivery/queue reliability, and firewall validation readiness.  
**Execution limits:** Repository source and test files were inspected through GitHub. No repository checkout was executed in an isolated local runtime during this review. No live dashboard, recipient, firewall, host-restart, or customer test was run. Findings below are source/test-evidence findings, not claims of successful exploit reproduction.

## Executive assessment

Sentinel is **not cleared for unrestricted production deployment or an unsupervised customer pilot** by this review. The 242-test local result supplied by the project owner and the successful post-merge CI are useful regression evidence, but they do not establish browser security, real message receipt, safe firewall application on customer hosts, or recovery after real power loss.

Two high-priority dashboard issues are confirmed by source inspection: a viewer-token control-mode privilege escalation when control is already enabled in configuration, and unsafe insertion of live threat fields into HTML with `innerHTML`. Additional token-handling and installer configuration-preservation gaps require remediation or explicit risk acceptance.

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

## Final disposition

**Status: NOT CLEARED for unrestricted production or unsupervised customer pilot.**  
**Suitable next stage:** isolated remediation and controlled evaluation, with no customer production changes.  
**Not performed:** live customer testing, real recipient delivery, firewall apply, deployment, release, package publication, or merge to `main`.

This audit records source-level findings and test gaps as of the reviewed baseline. It is not a penetration test, certification, or guarantee that no other vulnerabilities exist.
