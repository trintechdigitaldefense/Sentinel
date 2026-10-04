# Mobile / Operator setup — Sentinel v2.2.0 Phase 1

You do **not** need to push files yourself. After clone:

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel
python3 assemble_engine.py
```

That writes full `sentinel.py` (Phase 1 wired).

Requires all of: `engine_chunks/part_0.b64` … `part_3.b64`

If a part is missing, contact TrinTech — Grok will re-push the chunk.

Then:
```bash
python3 sentinel.py phase1
python3 sentinel.py onboard --client "Your Client"
```
