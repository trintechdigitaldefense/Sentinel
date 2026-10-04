# Phase 1 Implementation — Sentinel

## 1. TLS + Token Agent Channel

- Keep `X-Sentinel-Token` header (already required)
- Optional TLS: set `agent.use_tls: true` and paths to cert/key
- Central refuses plaintext if `require_tls: true`
- Agents send token on every report; 401 on mismatch

## 2. Auto-Quarantine Playbook

On high-severity alerts (`REVERSE_SHELL`, `CANARY_TRIGGERED`, `AGENT_REVERSE_SHELL`):

| Action | Command / method |
|--------|------------------|
| Block source IP | iptables DROP (reuse SSH blocklist store) |
| Kill process | `kill -9 <pid>` when PID known |
| Disable user | optional `usermod -L` (config flag) |
| Snapshot | copy canary/process evidence to `data/quarantine/` |

Config:
```json
"quarantine": {
  "enabled": true,
  "on_alerts": ["REVERSE_SHELL", "CANARY_TRIGGERED", "AGENT_REVERSE_SHELL"],
  "block_ip": true,
  "kill_process": true,
  "lock_user": false
}
```

## 3. Quiet Mode + False-Positive Tuning

```json
"quiet": {
  "enabled": false,
  "min_severity": "high",
  "suppress_types": [],
  "rate_limit_minutes": 15,
  "whitelist_processes": ["sentinel", "systemd"],
  "whitelist_ips": []
}
```

- Only emit console/email for severity ≥ threshold
- Rate-limit duplicate alert types
- Skip known-good process name fragments

## 4. Canary Beacon Callbacks

- Embed unique beacon URL or local marker in decoy files
- Optional: HTTP callback to central `/canary/beacon?id=CANARY_ID`
- On beacon hit → `CANARY_BEACON` alert + optional quarantine

## 5. One-Command Onboarding

```bash
sentinel onboard --client "Acme Ltd" [--subnets 192.168.1.0/24]
```

Does:
1. Generate unique shared_token
2. Write client name into config
3. Run deception + integrity baseline
4. Print agent install one-liner
5. Optionally enable systemd central

---

## CLI additions (Phase 1)

| Command | Purpose |
|---------|---------|
| `sentinel onboard --client NAME` | Client onboarding |
| `sentinel quarantine --status` | Show quarantine actions |
| `sentinel quiet on\|off` | Toggle quiet mode |
| `sentinel phase1` | Run Phase 1 self-check |

---

See `modules/phase1.py` for implementation modules integrated into `sentinel.py`.
