# Milestone 7 — residual risk mitigations

| Residual | Mitigation on branch |
|----------|----------------------|
| H-04 query token | Bearer + HttpOnly cookie preferred; query for first load; JS API uses Authorization |
| Live FW apply not in CI | Dry-run contract tests; live apply still manual on disposable VM |
| Alert channel chaos | dedup atomic path + offline_enqueue smoke under simulated conditions |
| Heuristic FP | confidence fields + disclaimer on realtime snapshot |
| Actions green | Fixed F821 `bp` in ransomware_tripwire (broke ruff on CI) |

Owner still confirms GitHub Actions green before merge.
