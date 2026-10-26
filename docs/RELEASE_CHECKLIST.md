# Release checklist (gates)

Do **not** mark a production release until each item has evidence (CI log, test output, or signed review).

- [ ] No unresolved Critical findings in `docs/SECURITY_AUDIT.md`
- [ ] Dashboard control routes: authz tests pass
- [ ] Install/upgrade preserves user data by default (no silent hard reset)
- [ ] Firewall dry-run default + recovery validated in disposable VM
- [ ] High-severity alerts survive simulated delivery failure + restart
- [ ] Doctor never reports CLIENT-READY / production-ready when required controls FAIL or UNKNOWN
- [ ] Full CI green on the release commit
- [ ] Install, upgrade, rollback, uninstall docs verified
- [ ] No real secrets in tree
- [ ] README claims match tested behavior
- [ ] Known limitations documented
- [ ] Owner-reviewed RC and rollback plan

Last audit revision referenced: see SECURITY_AUDIT.md header.
