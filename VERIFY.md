# Verify your install

```bash
python3 setup.py --check
python3 -m py_compile sentinel.py
pytest -q tests/ --tb=line
python3 sentinel.py doctor
```

Full notes: [docs/TESTING.md](docs/TESTING.md) · release gates: [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md)
