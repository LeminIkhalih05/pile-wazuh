#!/usr/bin/env bash
# verifier.sh : etat de tous les services du serveur (Tyk, Prometheus, Grafana, Wazuh), en une commande
set -uo pipefail
cd "$(dirname "$0")"
ko=0
ok()   { printf '  \e[32m[OK]\e[0m %s\n' "$1"; }
fail() { printf '  \e[31m[KO]\e[0m %s\n' "$1"; ko=1; }
titre() { printf '\n== %s ==\n' "$1"; }

titre "Conteneurs Docker"
docker ps -a --format '{{.Names}}|{{.State}}|{{.Status}}' | sort | while IFS='|' read -r n s st; do
  [ "$s" = running ] && ok "$n ($st)" || { printf '  \e[31m[KO]\e[0m %s (%s)\n' "$n" "$st"; }
done
[ -z "$(docker ps -a --filter status=exited --filter status=dead --filter status=restarting -q)" ] || ko=1

titre "Passerelle Tyk"
T=$(docker ps -q --filter label=com.docker.compose.service=tyk-gateway | head -1)
if [ -n "$T" ]; then
  PT=$(docker port "$T" 8443/tcp 2>/dev/null | head -1 | sed 's/.*://')
  c=$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost:${PT:-443}/hello")
  [ "$c" = 200 ] && ok "Tyk repond (https://localhost:${PT:-443}/hello : $c)" || fail "Tyk : /hello repond $c"
else
  echo "  (pas de conteneur tyk-gateway sur ce serveur)"
fi

titre "Prometheus"
P=$(docker ps -q --filter label=com.docker.compose.service=prometheus | head -1)
if [ -n "$P" ]; then
  docker exec "$P" wget -qO- 'http://localhost:9090/api/v1/targets?state=active' 2>/dev/null | python3 -c '
import json,sys
for t in json.load(sys.stdin)["data"]["activeTargets"]:
    print({"up":"OK","unknown":"ATT"}.get(t["health"],"KO"), t["labels"]["job"], t["scrapeUrl"], t.get("lastError",""))' \
  > /tmp/cibles.$$ || true
  while read -r e job url err; do case $e in OK) ok "cible $job ($url)";; ATT) echo "  [..] cible $job ($url) : premiere collecte en cours";; *) fail "cible $job ($url) $err";; esac; done < /tmp/cibles.$$
  rm -f /tmp/cibles.$$
  n=$(docker exec "$P" wget -qO- 'http://localhost:9090/api/v1/alerts' 2>/dev/null | python3 -c 'import json,sys;print(sum(1 for a in json.load(sys.stdin)["data"]["alerts"] if a["state"]=="firing"))' 2>/dev/null)
  [ "${n:-0}" = 0 ] && ok "aucune alerte Prometheus en cours" || fail "${n} alerte(s) Prometheus en cours (http://localhost:9090/alerts)"
else
  echo "  (pas de conteneur prometheus sur ce serveur)"
fi

titre "Grafana"
G=$(docker ps -q --filter label=com.docker.compose.service=grafana | head -1)
if [ -n "$G" ]; then
  GP=$(docker port "$G" 3000/tcp | head -1 | sed 's/0.0.0.0/127.0.0.1/')
  curl -sf "http://${GP:-127.0.0.1:3000}/api/health" | grep -q '"database": *"ok"' && ok "Grafana repond ($GP)" || fail "Grafana ne repond pas"
else
  echo "  (pas de conteneur grafana sur ce serveur)"
fi

titre "Wazuh"
./test.sh 2>&1 | sed 's/^/  /' || ko=1
if systemctl is-active --quiet wazuh-agent 2>/dev/null; then ok "agent Wazuh de ce serveur actif"; else echo "  (pas d'agent Wazuh sur ce serveur)"; fi

echo
[ $ko -eq 0 ] && echo "RESULTAT : tous les services sont operationnels" || echo "RESULTAT : au moins un service est en defaut (lignes [KO])"
exit $ko
