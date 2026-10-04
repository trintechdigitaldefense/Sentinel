# Sentinel — Mobile setup (Phase 1 + 2)

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel

# Engine v2.2
python3 assemble_engine.py

# Phase 2 module
python3 restore_phase2.py

# Wire Phase 2 into sentinel.py (→ v2.3.0)
python3 restore_wire_phase2.py
python3 wire_phase2.py

# Verify
python3 sentinel.py phase1
python3 sentinel.py phase2
python3 sentinel.py mirage --industry accounting
python3 sentinel.py score
python3 sentinel.py timeline
```

TrinTech Digital Defense
