# SENTINEL Phase 7 — Scale (v2.6)

## 6. Multi-host central status
```bash
python3 sentinel.py central          # http://HOST:8790/
python3 sentinel.py agents           # list
python3 sentinel.py agent-report     # register this host
python3 sentinel.py agent-report --central http://CENTRAL:8790
```

## 7. Windows agent (limited)
`agents/sentinel_win_agent.py` — process count + heartbeat → central.
```bash
python sentinel_win_agent.py --central http://CENTRAL:8790
```

## 8. Release v2.6
```bash
python3 sentinel.py release
git tag -a v2.6.0 -m "SENTINEL 2.6.0"
git push origin v2.6.0
```

## 9. Quiet hours
```bash
python3 sentinel.py quiet --on
python3 sentinel.py quiet --start 22:00 --end 07:00
python3 sentinel.py quiet --off
```
Critical alerts (reverse shell / canary) still fire when `allow_critical` is true.
