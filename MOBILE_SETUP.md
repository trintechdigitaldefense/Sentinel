# Sentinel mobile setup (Phase 1–4)

**WhatsApp reports:** +1 868 362-0679

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel
git pull

python3 assemble_engine.py

python3 restore_phase2.py && python3 restore_wire_phase2.py && python3 wire_phase2.py
python3 restore_phase3.py && python3 wire_phase3.py
python3 restore_phase4.py && python3 wire_phase4.py

python3 sentinel.py phase4
python3 sentinel.py baseline
python3 sentinel.py caribbean
python3 sentinel.py playbook REVERSE_SHELL
python3 sentinel.py evidence --hours 24
```

CallMeBot apikey once → `alerting.whatsapp.apikey` in `~/.sentinel/config.json`
