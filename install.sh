#!/usr/bin/env bash
# One-line installer: curl -sSL <raw>/install.sh | bash
# Always syncs to origin/main (hard reset) unless SENTINEL_KEEP_LOCAL=1
# Authorized defensive deployments only — TrinTech Digital Defense
set -euo pipefail

REPO_URL="${SENTINEL_REPO:-https://github.com/trintechdigitaldefense/Sentinel.git}"
DEST="${SENTINEL_HOME:-$HOME/Sentinel}"
BRANCH="${SENTINEL_BRANCH:-main}"

echo "=== SENTINEL installer (TrinTech Digital Defense) ==="

if ! command -v git >/dev/null; then
  echo "[!] git required"; exit 1
fi
if ! command -v python3 >/dev/null; then
  echo "[!] python3 required"; exit 1
fi

sync_repo() {
  local dir="$1"
  echo "[*] Syncing $dir → origin/$BRANCH (hard reset)"
  git -C "$dir" remote set-url origin "$REPO_URL" 2>/dev/null || true
  git -C "$dir" fetch origin --tags --prune
  # Prefer remote branch; fall back to main/master
  if git -C "$dir" rev-parse --verify "origin/$BRANCH" >/dev/null 2>&1; then
    git -C "$dir" checkout -B "$BRANCH" "origin/$BRANCH"
    git -C "$dir" reset --hard "origin/$BRANCH"
  else
    echo "[!] origin/$BRANCH missing — trying origin/main"
    git -C "$dir" checkout -B main origin/main
    git -C "$dir" reset --hard origin/main
  fi
  git -C "$dir" clean -fd
  echo "[+] HEAD: $(git -C "$dir" rev-parse --short HEAD) ($(git -C "$dir" describe --tags --always 2>/dev/null || echo no-tag))"
}

if [ -d "$DEST/.git" ]; then
  if [ "${SENTINEL_KEEP_LOCAL:-0}" = "1" ]; then
    echo "[*] SENTINEL_KEEP_LOCAL=1 — soft pull only (may leave stale tree)"
    git -C "$DEST" pull --ff-only || echo "[!] ff-only pull failed — re-run without SENTINEL_KEEP_LOCAL=1"
  else
    # Discard local edits to sentinel.py / setup artifacts so install matches GitHub
    if ! git -C "$DEST" diff --quiet || ! git -C "$DEST" diff --cached --quiet || [ -n "$(git -C "$DEST" ls-files --others --exclude-standard)" ]; then
      echo "[!] Local changes detected in $DEST — resetting to origin/$BRANCH"
      git -C "$DEST" status -sb || true
    fi
    sync_repo "$DEST"
  fi
else
  echo "[*] Cloning to $DEST"
  # If DEST exists but is not a git repo, move it aside
  if [ -e "$DEST" ]; then
    BAK="${DEST}.bak.$(date +%Y%m%d%H%M%S)"
    echo "[!] $DEST exists but is not a git clone — moving to $BAK"
    mv "$DEST" "$BAK"
  fi
  git clone --branch "$BRANCH" "$REPO_URL" "$DEST" || git clone "$REPO_URL" "$DEST"
  sync_repo "$DEST"
fi

cd "$DEST"

# Never run legacy stabilize/assemble on a clean tree
if [ -f stabilize.py ] || [ -f assemble_engine.py ]; then
  echo "[=] Note: legacy stabilize/assemble scripts may exist; setup.py does not invoke them"
fi

echo "[*] Running python3 setup.py"
python3 setup.py

if [ -f scripts/apply_cases_wire.py ]; then
  python3 scripts/apply_cases_wire.py || true
fi

# Quick compile gate
if ! python3 -c "import py_compile; py_compile.compile('sentinel.py', doraise=True)"; then
  echo "[!] sentinel.py failed to compile after install"
  exit 1
fi

echo
echo "========================================================"
echo "  INSTALL COMPLETE"
echo "========================================================"
echo "  cd $DEST"
echo "  python3 sentinel.py doctor"
echo "  python3 sentinel.py go-live"
echo "  python3 sentinel.py service-install"
echo "  python3 sentinel.py dashboard"
echo
echo "  Re-install / force sync anytime:"
echo "    bash install.sh"
echo "  Or: git -C $DEST fetch origin && git -C $DEST reset --hard origin/main"
echo "========================================================"
