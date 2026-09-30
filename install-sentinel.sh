#!/bin/bash
# Sentinel Client-Ready Installer — TrinTech Digital Defense
# Usage: sudo bash install-sentinel.sh [--central|--agent CENTRAL_URL]

set -euo pipefail

SENTINEL_SRC="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/sentinel"
DATA_DIR="/root/.sentinel"
SERVICE_DIR="/etc/systemd/system"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}[*] TrinTech Sentinel — Client-Ready Installer${NC}"

if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}[-] Run as root (sudo)${NC}"
  exit 1
fi

MODE="central"
CENTRAL_URL=""
if [[ "${1:-}" == "--agent" ]]; then
  MODE="agent"
  CENTRAL_URL="${2:-}"
  if [[ -z "$CENTRAL_URL" ]]; then
    echo -e "${RED}[-] Usage: $0 --agent http://CENTRAL_IP:8743${NC}"
    exit 1
  fi
fi

echo -e "${CYAN}[*] Installing to ${INSTALL_DIR}${NC}"
mkdir -p "$INSTALL_DIR"
cp -f "$SENTINEL_SRC/sentinel.py" "$INSTALL_DIR/sentinel.py"
chmod 755 "$INSTALL_DIR/sentinel.py"

# Symlink for convenience
ln -sf "$INSTALL_DIR/sentinel.py" /usr/local/bin/sentinel

# Data directory permissions
mkdir -p "$DATA_DIR/data"
chmod 700 "$DATA_DIR"
chmod 700 "$DATA_DIR/data" 2>/dev/null || true

# Generate token if missing
python3 - <<'PY'
import json, secrets
from pathlib import Path
cfg_path = Path("/root/.sentinel/config.json")
cfg_path.parent.mkdir(parents=True, exist_ok=True)
if cfg_path.exists():
    cfg = json.loads(cfg_path.read_text())
else:
    cfg = {}
agent = cfg.setdefault("agent", {})
if not agent.get("shared_token"):
    agent["shared_token"] = secrets.token_urlsafe(32)
    agent["port"] = 8743
    agent["enabled"] = True
    agent["report_interval"] = 60
    cfg_path.write_text(json.dumps(cfg, indent=2))
    print("[+] Generated new shared_token")
else:
    print("[+] Existing shared_token retained")
print("Token:", agent.get("shared_token"))
PY

chmod 600 /root/.sentinel/config.json 2>/dev/null || true

# systemd units
if [[ "$MODE" == "central" ]]; then
cat > "$SERVICE_DIR/sentinel-central.service" <<EOF
[Unit]
Description=Sentinel Central - TrinTech Digital Defense
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/sentinel.py central
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/root/.sentinel

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  echo -e "${GREEN}[+] Central service installed${NC}"
  echo "    Enable with: systemctl enable --now sentinel-central"
else
cat > "$SERVICE_DIR/sentinel-agent.service" <<EOF
[Unit]
Description=Sentinel Agent - TrinTech Digital Defense
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/sentinel.py agent $CENTRAL_URL
Restart=always
RestartSec=15
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/root/.sentinel

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  echo -e "${GREEN}[+] Agent service installed (target: $CENTRAL_URL)${NC}"
  echo "    Enable with: systemctl enable --now sentinel-agent"
fi

# logrotate
cat > /etc/logrotate.d/sentinel <<'EOF'
/root/.sentinel/data/alerts.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    create 600 root root
}
EOF

echo -e "${GREEN}[+] Install complete${NC}"
echo ""
echo "Next steps:"
echo "  1. Review token in /root/.sentinel/config.json"
echo "  2. Same token must exist on every agent"
echo "  3. Run: sentinel deception && sentinel integrity"
echo "  4. Start service as shown above"
echo "  5. Read CLIENT_READY.md before any client deployment"
