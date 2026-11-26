#!/usr/bin/env bash
set -euo pipefail
[[ $EUID != 0 ]] || { echo 'Run as your normal user, not root';exit 1; }
cd "$(dirname "$0")"
D="$HOME/.config/nexus-agent"; U="$HOME/.config/systemd/user/nexus-agent.service"
case "${1:-install}" in
uninstall) systemctl --user disable --now nexus-agent.service || true;rm -f "$U" "$D/agent-linux.py" "$D/token" "$D/server.txt" "$D/ca.crt";rmdir "$D" 2>/dev/null || true;systemctl --user daemon-reload;echo 'Local agent removed; revoke its server identity separately.';exit;;
install) ;;
*) echo 'Usage: bash setup-linux.sh [install|uninstall]';exit 2;;esac
command -v python3;systemctl --user show-environment >/dev/null
umask 077;mkdir -p "$D" "$(dirname "$U")";chmod 700 "$D"
read -rp 'HTTPS NEXUS origin: ' base
python3 - "$base" <<'PY'
import sys,urllib.parse
u=urllib.parse.urlsplit(sys.argv[1]);assert u.scheme=='https' and u.hostname and not u.username and not u.password and u.path in ('','/') and not u.query and not u.fragment
PY
if [[ -f "$D/token" && ( ! -f "$D/server.txt" || $(cat "$D/server.txt") != "$base" ) ]];then echo 'Existing token may belong to another server. Uninstall and pair again first.';exit 1;fi
read -rp 'Path to verified NEXUS CA certificate (blank for system trust): ' ca
if [[ -n "$ca" ]];then install -m 0600 "$ca" "$D/ca.crt";fi
printf '%s\n' "$base" > "$D/server.txt";install -m 0700 agent-linux.py "$D/agent-linux.py"
python3 "$D/agent-linux.py" --pair-only
cat > "$U" <<'EOF'
[Unit]
Description=NEXUS user telemetry agent
[Service]
ExecStart=/usr/bin/python3 %h/.config/nexus-agent/agent-linux.py --run
Restart=on-failure
RestartSec=30
NoNewPrivileges=yes
[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload;systemctl --user enable --now nexus-agent.service
systemctl --user status nexus-agent.service --no-pager
