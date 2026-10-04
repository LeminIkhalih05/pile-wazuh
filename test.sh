#!/usr/bin/env bash
# test.sh : verifie que la pile Wazuh repond (a lancer sur vm-siem, dans le dossier du projet)
set -uo pipefail
cd "$(dirname "$0")"
set -a; . ./.env; set +a
ko=0
ok()   { echo "[OK] $1"; }
fail() { echo "[KO] $1"; ko=1; }

for s in wazuh.manager wazuh.indexer wazuh.dashboard; do
  [ "$(docker compose ps -q "$s" | xargs -r docker inspect -f '{{.State.Running}}' 2>/dev/null)" = "true" ] \
    && ok "conteneur $s demarre" || fail "conteneur $s arrete (docker compose logs $s)"
done

h=$(curl -sk -u "admin:${INDEXER_ADMIN_PASSWORD}" https://localhost:9200/_cluster/health | python3 -c 'import sys,json;print(json.load(sys.stdin)["status"])' 2>/dev/null)
[[ "$h" == green || "$h" == yellow ]] && ok "indexer : etat $h" || fail "indexer injoignable ou mot de passe refuse"

t=$(curl -sk -u "wazuh-wui:${API_PASSWORD}" -X POST "https://localhost:55000/security/user/authenticate?raw=true")
[[ "$t" == ey* ]] && ok "API Wazuh : authentification wazuh-wui" || fail "API Wazuh : authentification refusee"

c=$(curl -sk -o /dev/null -w '%{http_code}' https://localhost/)
[[ "$c" == 200 || "$c" == 302 ]] && ok "tableau de bord : HTTPS $c" || fail "tableau de bord : code $c"

for p in 1514 1515; do
  (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null && ok "port agents $p ouvert" || fail "port agents $p ferme"
done

if [ -n "${t:-}" ] && [[ "$t" == ey* ]]; then
  n=$(curl -sk -H "Authorization: Bearer $t" "https://localhost:55000/agents?status=active&limit=1" \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["total_affected_items"])' 2>/dev/null)
  echo "[..] agents actifs (manager compris) : ${n:-?}"
fi

[ $ko -eq 0 ] && echo "Tout est OK. Tableau de bord : https://$(hostname -I | awk '{print $1}')  (compte admin, mot de passe INDEXER_ADMIN_PASSWORD du .env)"
exit $ko
