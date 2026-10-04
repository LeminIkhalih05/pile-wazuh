#!/usr/bin/env bash
# setup.sh : prepare et lance la pile Wazuh (a executer une fois, dans le dossier du projet)
#   1. reglage noyau pour l'indexer   2. secrets dans .env   3. empreintes des mots de passe
#   4. certificats (openssl, hors ligne)  5. demarrage       6. groupe gateway + mot de passe d'enrolement
set -euo pipefail
cd "$(dirname "$0")"

command -v docker >/dev/null || { echo "Docker absent : lancer d'abord ./install-docker.sh"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 absent"; exit 1; }

# 1. Reglage noyau exige par l'indexer (OpenSearch)
if [ "$(sysctl -n vm.max_map_count)" -lt 262144 ]; then
  echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/90-wazuh.conf >/dev/null
  sudo sysctl -q -w vm.max_map_count=262144
  echo "[OK] vm.max_map_count=262144"
fi

# 2. Secrets (generes une seule fois). Format : 20 caracteres aleatoires + Aa1. (regles de complexite Wazuh)
genpw() { printf '%s%s' "$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 20)" 'Aa1.'; }
[ -f .env ] || cp .env.example .env
chmod 600 .env
for v in INDEXER_ADMIN_PASSWORD DASHBOARD_PASSWORD API_PASSWORD ENROLLMENT_PASSWORD; do
  if grep -q "^${v}=$" .env; then
    sed -i "s/^${v}=$/${v}=$(genpw)/" .env
    echo "[OK] ${v} genere dans .env (a copier dans votre coffre a mots de passe)"
  fi
done
# Port du tableau de bord : 443, ou 8443 si 443 est deja pris par un autre service
grep -q '^DASHBOARD_PORT=' .env || echo 'DASHBOARD_PORT=' >> .env
if grep -q '^DASHBOARD_PORT=$' .env; then
  if (exec 3<>/dev/tcp/127.0.0.1/443) 2>/dev/null || { command -v ss >/dev/null && ss -Hltn 'sport = :443' | grep -q .; }; then P=8443; else P=443; fi
  sed -i "s/^DASHBOARD_PORT=$/DASHBOARD_PORT=${P}/" .env
  echo "[OK] Port du tableau de bord : ${P}"
fi
set -a; . ./.env; set +a
for v in WAZUH_VERSION INDEXER_HEAP INDEXER_ADMIN_PASSWORD DASHBOARD_PASSWORD API_PASSWORD ENROLLMENT_PASSWORD; do
  [ -n "${!v:-}" ] || { echo "[KO] $v vide dans .env"; exit 1; }
done

# 3. Fichiers de configuration avec secrets (crees une seule fois, avant le premier demarrage :
#    l'indexer charge internal_users.yml uniquement a l'initialisation de sa base de securite)
hashpw() {
  docker run --rm -e PW="$1" "wazuh/wazuh-indexer:${WAZUH_VERSION}" bash -c \
    'bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$PW"' 2>/dev/null | grep '^\$2' | tail -1
}
if [ ! -f config/wazuh_indexer/internal_users.yml ]; then
  echo "[..] Calcul des empreintes bcrypt (telechargement de l'image indexer au premier passage)"
  ADMIN_HASH=$(hashpw "$INDEXER_ADMIN_PASSWORD") || true; KS_HASH=$(hashpw "$DASHBOARD_PASSWORD") || true
  [ -n "$ADMIN_HASH" ] && [ -n "$KS_HASH" ] || { echo "[KO] Calcul des empreintes impossible (Docker demarre ? image indexer telechargeable ?)"; exit 1; }
  ADMIN_HASH="$ADMIN_HASH" KS_HASH="$KS_HASH" python3 - <<'PY'
import os
src = open('config/wazuh_indexer/internal_users.yml.modele').read()
src = src.replace('__ADMIN_HASH__', os.environ['ADMIN_HASH']).replace('__KIBANASERVER_HASH__', os.environ['KS_HASH'])
open('config/wazuh_indexer/internal_users.yml', 'w').write(src)
PY
  echo "[OK] internal_users.yml genere"
fi
python3 - <<'PY'
import os
src = open('config/wazuh_dashboard/wazuh.yml.modele').read()
open('config/wazuh_dashboard/wazuh.yml', 'w').write(src.replace('__API_PASSWORD__', os.environ['API_PASSWORD']))
PY
# les conteneurs lisent ces fichiers avec leur propre utilisateur
chmod 644 config/wazuh_dashboard/wazuh.yml config/wazuh_indexer/internal_users.yml

# 4. Certificats internes (autorite + manager, indexer, tableau de bord)
sudo test -f config/wazuh_indexer_ssl_certs/root-ca.pem || ./generer-certs.sh

# 5. Demarrage
docker compose config --quiet
docker compose up -d
echo "[..] Attente du manager (1 a 2 minutes)"
# 6. Groupe "gateway" (FIM sur la configuration Tyk), cree des que tous les services du manager sont prets
ready=0
for i in $(seq 1 60); do
  if docker compose exec -T wazuh.manager sh -c \
      '[ -d /var/ossec/etc/shared/gateway ] || { /var/ossec/bin/agent_groups -q -a -g gateway; [ -d /var/ossec/etc/shared/gateway ]; }' >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 5
done
[ $ready -eq 1 ] || { echo "[KO] Le manager ne demarre pas : docker compose logs wazuh.manager"; exit 1; }
# Mot de passe d'enrolement des agents
docker compose exec -T -e P="$ENROLLMENT_PASSWORD" wazuh.manager sh -c \
  'printf "%s\n" "$P" > /var/ossec/etc/authd.pass && chown root:wazuh /var/ossec/etc/authd.pass && chmod 640 /var/ossec/etc/authd.pass'
docker compose cp agents/groupes/gateway/agent.conf wazuh.manager:/var/ossec/etc/shared/gateway/agent.conf
docker compose exec -T wazuh.manager chown wazuh:wazuh /var/ossec/etc/shared/gateway/agent.conf
docker compose restart wazuh.manager
echo "[OK] Enrolement protege par mot de passe, groupe gateway pret"

echo "[..] Demarrage de l'indexer et du tableau de bord (2 a 3 minutes)"
for i in $(seq 1 60); do
  curl -sk -o /dev/null -w '%{http_code}' https://localhost:${DASHBOARD_PORT}/ 2>/dev/null | grep -qE '^(200|302)$' && break; sleep 5
done
for i in $(seq 1 36); do
  curl -sk -u "wazuh-wui:${API_PASSWORD}" -X POST "https://localhost:55000/security/user/authenticate?raw=true" 2>/dev/null | grep -q '^ey' && break; sleep 5
done
./test.sh
