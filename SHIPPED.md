# SENTINEL pre-wired engine (v2.9.8)

`sentinel.py` in this repo is a **stabilized, client-ready engine**.

## Client install (recommended)

```bash
git clone https://github.com/trintechdigitaldefense/Sentinel.git
cd Sentinel
python3 setup.py          # skips assemble when engine is complete
python3 sentinel.py doctor
python3 sentinel.py deception
python3 sentinel.py hunt  # or: python3 sentinel.py service-install
python3 sentinel.py dash  # login dashboard
```

## When to force rebuild

```bash
python3 setup.py --force-assemble
```

Only if the engine file is missing/corrupt or you are developing wire scripts.

## What setup does on a good engine

1. Skip assemble
2. Run `stabilize.py` (safe, idempotent — rolls back broken wires)
3. Defaults + doctor
