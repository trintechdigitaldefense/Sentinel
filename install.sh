#!/usr/bin/env bash
# SENTINEL installer — TrinTech Digital Defense
# Default: non-destructive (clone or fast-forward only).
# Recovery hard-reset: SENTINEL_RECOVER_SYNC=1 bash install.sh
set -euo pipefail

REPO_URL="${SENTINEL_REPO:-https://github.com/trintechdigitaldefense/Sentinel.git}"
DEST="${SENTINEL_HOME:-$HOME/Sentinel}"
BRANCH="${SENTINEL_BRANCH:-main}"

echo "=== SENTINEL installer (TrinTech Digital Defense) ==="

if ! command -v git >/dev/null; then echo "[!] git required"; exit 1; fi
if ! command -v python3 >/dev/null; then echo "[!] python3 required"; exit 1; fi

ff_upgrade() {
  local dir="$1"
  echo "[*] Safe upgrade: fetch + fast-forward only ($dir)"
  git -C "$dir" remote set-url origin "$REPO_URL" 2>/dev/null || true
  git -C "$dir" fetch origin --tags --prune
  if ! git -C "$dir" rev-parse --verify "origin/$BRANCH" >/dev/null 2>&1; then
    BRANCH=main
  fi
  # Stay on branch; try ff-only merge of origin
  git -C "$dir" checkout "$BRANCH" 2>/dev/null || git -C "$dir" checkout -B "$BRANCH" "origin/$BRANCH"
  if git -C "$dir" merge --ff-only "origin/$BRANCH"; then
    echo "[+] Fast-forward OK → $(git -C "$dir" rev-parse --short HEAD)"
  else
    echo "[!] Fast-forward failed (local commits or dirty tree)."
    echo "    Options:"
    echo "      1) Commit or stash your changes, then re-run install.sh"
    echo "      2) Explicit recovery (DESTROYS uncommitted work):"
    echo "           SENTINEL_RECOVER_SYNC=1 bash install.sh"
    exit 2
  fi
}

recover_sync() {
  local dir="$1"
  echo "[!] RECOVERY MODE: hard reset to origin/$BRANCH (uncommitted changes LOST)"
  echo "    Waiting 3s — Ctrl+C to abort..."
  sleep 3
  git -C "$dir" fetch origin --tags --prune
  git -C "$dir" checkout -B "$BRANCH" "origin/$BRANCH"
  git -C "$dir" reset --hard "origin/$BRANCH"
  # Do NOT git clean -fd by default even in recovery; optional
  if [ "${SENTINEL_RECOVER_CLEAN:-0}" = "1" ]; then
    echo "[!] Also removing untracked files (SENTINEL_RECOVER_CLEAN=1)"
    git -C "$dir" clean -fd
  fi
  echo "[+] Recovered → $(git -C "$dir" rev-parse --short HEAD)"
}

if [ -d "$DEST/.git" ]; then
  if [ "${SENTINEL_RECOVER_SYNC:-0}" = "1" ]; then
    recover_sync "$DEST"
  else
    # Warn if dirty but do not destroy
    if ! git -C "$DEST" diff --quiet || ! git -C "$DEST" diff --cached --quiet; then
      echo "[!] Uncommitted changes present in $DEST — will try fast-forward only"
      git -C "$DEST" status -sb || true
    fi
    ff_upgrade "$DEST"
  fi
else
  echo "[*] First-time clone → $DEST"
  if [ -e "$DEST" ] && [ ! -d "$DEST/.git" ]; then
    BAK="${DEST}.bak.$(date +%Y%m%d%H%M%S)"
    echo "[!] $DEST exists and is not a git repo — moving aside to $BAK"
    mv "$DEST" "$BAK"
  fi
  git clone --branch "$BRANCH" "$REPO_URL" "$DEST" || git clone "$REPO_URL" "$DEST"
fi

cd "$DEST"
echo "[*] python3 setup.py"
python3 setup.py

if ! python3 -c "import py_compile; py_compile.compile('sentinel.py', doraise=True)"; then
  echo "[!] sentinel.py failed to compile"; exit 1
fi

echo
echo "========================================================"
echo "  INSTALL COMPLETE (non-destructive default)"
echo "========================================================"
echo "  cd $DEST"
echo "  python3 sentinel.py doctor"
echo "  Recovery only if needed: SENTINEL_RECOVER_SYNC=1 bash install.sh"
echo "========================================================"
