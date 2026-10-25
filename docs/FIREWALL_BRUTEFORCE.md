# Firewall + SSH brute-force (v3.7)

## Architecture

```
auth logs / journald
        │
        ▼
 modules/brute_force.py   parse failures, threshold, expire
        │
        ▼
 modules/firewall.py      block_ip (nft/iptables, lockout guard, audit)
        │
        ▼
  host INPUT drop + ~/.sentinel/data/iptables_blocklist.json
```

## Config (`~/.sentinel/config.json`)

```json
"ssh_blocking": {
  "active": true,
  "max_failures": 5,
  "block_duration": 1800,
  "auto_block": true,
  "alert_on_block": true,
  "whitelist_ips": ["203.0.113.10"]
}
```

## CLI

```bash
python3 sentinel.py ssh-blocks status
python3 sentinel.py ssh-blocks check
python3 sentinel.py ssh-blocks expire
python3 sentinel.py ssh-blocks whitelist 203.0.113.10
python3 sentinel.py firewall status
python3 sentinel.py firewall harden-ssh          # dry-run
python3 sentinel.py firewall harden-ssh --confirm
python3 sentinel.py firewall expire-blocks
```

## Safety

- Operator SSH IPs are never blocked (lockout guard)
- Whitelist overrides auto-block
- Dry-run remains default for manual `firewall block`
- Auto-block from hunt uses `--confirm` path inside the control plane only
