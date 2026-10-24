#!/usr/bin/env bash
# One-line installer: curl -sSL <raw>/install.sh | bash
# Authorized defensive deployments only — TrinTech Digital Defense
set -euo pipefail
REPO_URL="${SENTINEL_REPO:-https://github.com/trintechdigitaldefense/Sentinel.git}"
DEST="${SENTINEL_HOME:-$HOME/Sentinel}"

echo "=== SENTINEL installer (TrinTech Digital Defense) ==="
if ! command -v git >/dev/null; then
  echo "git required"; exit 1
fi
if ! command -v python3 >/dev/null; then
  echo "python3 required"; exit 1
fi

if [ -d "$DEST/.git" ]; then
  echo "[*] Updating existing clone at $DEST"
  git -C "$DEST" pull --ff-only || true
else
  echo "[*] Cloning to $DEST"
  git clone "$REPO_URL" "$DEST"
fi
cd "$DEST"
python3 setup.py
# Ensure cases wire is applied (also invoked from setup.py)
if [ -f scripts/apply_cases_wire.py ]; then
  python3 scripts/apply_cases_wire.py || true
fi
echo
echo "Done. Run:  cd $DEST && python3 sentinel.py"
echo "Cases:      python3 sentinel.py cases list"
echo "Optional:   python3 sentinel.py service-install"
