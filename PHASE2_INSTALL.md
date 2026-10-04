# Phase 2 install

```bash
cd Sentinel
git pull
python3 restore_phase2.py   # if present, else phase2_a + phase2_b already load via modules/phase2.py
python3 -c "from modules.phase2 import mirage_deploy, phase2_self_check; print('Phase 2 OK')"
```

CLI (after wire into sentinel.py):
- sentinel mirage [--industry accounting|retail|medical|logistics|general]
- sentinel score
- sentinel timeline
- sentinel phase2
