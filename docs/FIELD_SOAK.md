# SENTINEL — Field soak

Authorized **friendly-site** proof that canaries, sim probes, and alert paths work.

## Command

```bash
python3 setup.py
python3 sentinel.py deception          # if needed
python3 sentinel.py integrity          # if needed
python3 sentinel.py field-soak
python3 sentinel.py field-soak --confirm   # runs defensive sim probes
```

Report: `~/.sentinel/data/field_soak_report.json`

## Checklist

- [ ] Written authorization for the host  
- [ ] Doctor / pilot has no hard FAILs  
- [ ] Canaries deployed  
- [ ] FIM baseline exists  
- [ ] `field-soak --confirm` completes  
- [ ] At least one alert path verified:
  - [ ] WhatsApp test, or  
  - [ ] `siem splunk health`, or  
  - [ ] `siem_ship.jsonl` growing  
- [ ] Critical open list reviewed (`critical status`)

## Safe probes only

Use built-in `sim` / field-soak scenarios. Do **not** launch real attacker tools on client production without a separate ROE.
