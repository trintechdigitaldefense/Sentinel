# SENTINEL — Threat-Actor Simulation (defensive)

Authorized **defensive** validation only. These scenarios exercise detectors
without real malware, reverse connections, or privilege escalation.

## Quick start

```bash
python3 sentinel.py sim --list
python3 sentinel.py sim --scenario all --confirm
python3 sentinel.py processes          # optional: catch live RS argv probe
python3 sentinel.py sim --scenario cleanup --confirm
```

## Scenarios

| Name | What it does | Expected signal |
|------|----------------|-----------------|
| `canary` | Reads/touches deployed decoys | Canary / SIM alert |
| `fim` | Modifies FIM-tracked probe file | `FIM_MODIFIED` |
| `persistence` | Drops temp user systemd timer | `NEW_PERSISTENCE` |
| `reverse_shell` | Short `sleep` whose **argv** contains RS strings | `REVERSE_SHELL` if scan runs |
| `behavioral` | Validates heuristic helpers | helpers OK, 0 hits clean host |
| `cleanup` | Removes sim artifacts | — |

## Safety

- Requires `--confirm`
- No outbound exploit callbacks (documentation IPs only in strings)
- No interactive shells (`bash -i` appears only as argv text on `sleep`)
- Does not modify real `authorized_keys` or `/etc/ld.so.preload`
- Artifacts under `~/.sentinel/data/sim/` and `~/.config/systemd/user/sentinel-sim-probe.*`

## Pilot use

```bash
python3 sentinel.py pilot --fix
python3 sentinel.py integrity
python3 sentinel.py deception
python3 sentinel.py sim --scenario all --confirm
python3 sentinel.py hunt   # observe alerts briefly
python3 sentinel.py sim --scenario cleanup --confirm
```
