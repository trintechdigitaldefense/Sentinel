# SENTINEL — Install, upgrade, recovery

## First-time install

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel
python3 setup.py
python3 sentinel.py doctor
```

Optional one-liner from a release tree:

```bash
bash install.sh
```

**Do not** run legacy `restore_phase*.py` / `assemble_engine.py` / `stabilize.py` on a modern tree.

## Upgrade (non-destructive)

```bash
cd ~/Sentinel
git fetch origin
git merge --ff-only origin/main   # or: git pull --ff-only
python3 setup.py
python3 sentinel.py doctor
```

If fast-forward fails, **stop**. Commit or stash local changes. Do not force-reset unless you intend to discard work.

## Recovery (destructive — explicit only)

Only when you deliberately want the tree to match `origin/main` and accept data loss of uncommitted files:

```bash
SENTINEL_RECOVER_SYNC=1 bash install.sh
# optional also remove untracked files:
SENTINEL_RECOVER_SYNC=1 SENTINEL_RECOVER_CLEAN=1 bash install.sh
```

## After setup (client go-live)

```bash
python3 sentinel.py go-live        # preferred bootstrap
# or stepwise:
python3 sentinel.py integrity
python3 sentinel.py deception
python3 sentinel.py service-install
python3 sentinel.py doctor
```

## Config

`~/.sentinel/config.json` — written with mode **0600** by setup.  
Data: `~/.sentinel/data/`.

## Uninstall

```bash
python3 sentinel.py uninstall
# type YES when prompted
```
