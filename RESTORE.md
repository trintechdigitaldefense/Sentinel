# Restore Sentinel v2.2.0 (Phase 1 Wired)

The full engine is shipped compressed to avoid GitHub connector size limits.

```bash
cd Sentinel
python3 restore_v22.py
# writes sentinel.py (~94KB) — Phase 1 fully wired
python3 sentinel.py phase1
python3 sentinel.py onboard --client "Test Client"
```

Requires `modules/phase1.py` (already in repo).
