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
echo
echo "Done. Run:  cd $DEST && python3 sentinel.py"
echo "Optional:   python3 sentinel.py service-install"
