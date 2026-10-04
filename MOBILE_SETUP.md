# Sentinel mobile setup (Phase 1–3)

**WhatsApp reports:** +1 868 362-0679

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel

python3 assemble_engine.py
python3 restore_phase2.py && python3 restore_wire_phase2.py && python3 wire_phase2.py
python3 restore_phase3.py && python3 wire_phase3.py

# One-time: get CallMeBot apikey
# WhatsApp +34 644 59 71 67 → "I allow callmebot to send me messages"
# Put apikey in ~/.sentinel/config.json → alerting.whatsapp.apikey

python3 sentinel.py phase3
python3 sentinel.py whatsapp-test
python3 sentinel.py weekly-report
python3 sentinel.py dashboard
```
