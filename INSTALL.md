# SENTINEL — Single install path

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel
python3 setup.py
python3 sentinel.py doctor
```

That is the only install. **Do not** run `restore_phase*.py`.

## After setup (client go-live)

```bash
python3 sentinel.py integrity      # FIM baseline
python3 sentinel.py deception      # canaries
python3 sentinel.py service-install
python3 sentinel.py doctor         # aim for OK + few WARNs
```

## Doctor

`python3 sentinel.py doctor` (aliases: `health`, `check`) reports:

- engine / modules / wired commands
- config + subnet (fails if /8-style ranges)
- permissions, FIM baseline, canaries
- heartbeat + systemd service
- WhatsApp (optional)

## Config

`~/.sentinel/config.json` — SMB defaults applied by setup (narrow subnet, WhatsApp off, quiet hours off).

## Force clean update (fixes stale local tree)

```bash
cd ~/Sentinel   # or your clone path
git fetch origin
git reset --hard origin/main
python3 setup.py
```

Or re-run the installer (hard-resets by default):

```bash
bash install.sh
```

Opt out of reset: `SENTINEL_KEEP_LOCAL=1 bash install.sh`

