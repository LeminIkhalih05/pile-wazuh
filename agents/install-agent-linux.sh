#!/usr/bin/env bash
# install-agent-linux.sh : installe et enrole l'agent Wazuh sur une VM Ubuntu / Debian
#   sudo ./install-agent-linux.sh <IP_MANAGER> <MOT_DE_PASSE_ENROLEMENT> [groupe]
#   ex. vm-gateway : sudo ./install-agent-linux.sh 192.168.12.103 '<ENROLLMENT_PASSWORD>' gateway
set -euo pipefail
MANAGER="${1:?IP du manager Wazuh}"
PASS="${2:?mot de passe d'enrolement (ENROLLMENT_PASSWORD du .env de vm-siem)}"
GROUP="${3:-default}"
VERSION="${WAZUH_VERSION:-4.14.8}"   # jamais plus recent que le manager
[ "$(id -u)" -eq 0 ] || { echo "Lancer avec sudo"; exit 1; }

apt-get update -q && apt-get install -y -q curl gpg
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update -q

WAZUH_MANAGER="$MANAGER" WAZUH_REGISTRATION_PASSWORD="$PASS" WAZUH_AGENT_GROUP="$GROUP" \
WAZUH_AGENT_NAME="$(hostname -s)" apt-get install -y -q "wazuh-agent=${VERSION}-1"
apt-mark hold wazuh-agent          # evite une mise a jour plus recente que le manager

systemctl daemon-reload
systemctl enable --now wazuh-agent
sleep 10
if grep -q "Connected to the server" /var/ossec/logs/ossec.log; then
  echo "[OK] Agent $(hostname -s) connecte a $MANAGER (groupe $GROUP)"
else
  echo "[..] Agent installe, connexion non confirmee : tail -f /var/ossec/logs/ossec.log"
fi
