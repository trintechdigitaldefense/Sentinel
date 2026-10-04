# Fix install (Phases 1–4)

Old `restore_phase*.py` zlib blobs were corrupted. Use this instead:

```bash
cd ~/Sentinel
git fetch origin
git reset --hard origin/main

python3 assemble_engine.py
python3 install_phases.py
python3 wire_phase2.py
python3 wire_phase3.py
python3 wire_phase4.py

python3 sentinel.py phase4
python3 sentinel.py baseline
python3 sentinel.py caribbean
```

WhatsApp default: +1-868-362-0679
