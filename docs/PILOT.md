# SENTINEL — Client Pilot Validation Workflow

Use this on every new client host before you leave the site.

## One command

```bash
cd Sentinel
python3 setup.py
python3 sentinel.py pilot
```

Optional:

```bash
python3 sentinel.py pilot --fix    # create missing persistence/SUID baselines
```

Report is written to: `~/.sentinel/data/pilot_report.json`

---

## Workflow phases

| Phase | What it validates |
|-------|-------------------|
| **1. Preflight** | Doctor (no FAILs), detection modules present |
| **2. Baselines** | Persistence, SUID, FIM integrity baseline |
| **3. Deception** | Canary / decoy artifacts deployed |
| **4. Detection** | Behavioral scan runs; firewall dry-run + lockout guard |
| **5. Service** | systemd or background hunt active |

## Go-live checklist

- [ ] Doctor has zero FAILs
- [ ] Persistence baseline exists
- [ ] SUID baseline exists
- [ ] FIM baseline exists (`python3 sentinel.py integrity`)
- [ ] Canaries deployed (`python3 sentinel.py deception`)
- [ ] Behavioral scan runs clean (or known hits explained)
- [ ] Firewall dry-run works; lockout guard on
- [ ] Continuous protection: `python3 sentinel.py service-install`

## Recommended order on site

```bash
python3 setup.py
python3 sentinel.py pilot          # see gaps
python3 sentinel.py integrity      # FIM + SUID
python3 sentinel.py deception      # canaries
python3 sentinel.py persistence-baseline
python3 sentinel.py service-install
python3 sentinel.py pilot          # confirm GO-LIVE READY
python3 sentinel.py doctor
```

## Safe live tests (optional, authorized only)

1. **Canary touch** — open one decoy file under a canary path; confirm alert/log entry.
2. **FIM** — `touch` is not enough; modify a non-critical baselined test file only in lab.
3. **Firewall dry-run** — `python3 sentinel.py firewall block 203.0.113.10` (no `--confirm`).

Do **not** run destructive tests on production without written client authorization.

## After pilot

- Save `~/.sentinel/data/pilot_report.json` in the engagement folder
- Enable WhatsApp/email if the client wants digests
- Schedule weekly integrity: document in handoff notes
