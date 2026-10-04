# Sentinel v2.2.0 — Mobile setup (Phase 1 complete)

All engine chunks are on GitHub. From any device:

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel
python3 assemble_engine.py
```

That writes full `sentinel.py` (~94KB) with Phase 1 wired:
- Quiet mode
- Auto-quarantine
- Canary beacons
- `sentinel onboard --client NAME`
- Token agent headers

## Verify

```bash
python3 sentinel.py phase1
python3 sentinel.py onboard --client "Test"
python3 sentinel.py --help   # or: python3 sentinel.py
```

## Chunks required

- `engine_chunks/part_0a.b64` + `part_0b.b64`
- `engine_chunks/part_1a.b64` + `part_1b.b64`
- `engine_chunks/part_2a.b64` + `part_2b.b64`
- `engine_chunks/part_3.b64`
- `assemble_engine.py`
- `modules/phase1.py`

TrinTech Digital Defense — Phase 1 complete.
