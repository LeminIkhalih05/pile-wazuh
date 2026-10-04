#!/usr/bin/env bash
# integrer-supervision.sh : relie la pile Wazuh au Prometheus et au Grafana deja en place sur ce serveur
#   1. Prometheus et Grafana rejoignent le reseau Docker de Wazuh (de facon permanente)
#   2. Prometheus collecte l'exporteur BCM (conteneurs, agents, alertes) et charge les alertes
#   3. Grafana recoit la source "Wazuh (alertes)" et deux tableaux de bord
#   4. Un agent Wazuh est installe sur ce serveur (journaux systeme et Docker, dont Tyk)
# Relancable sans risque. Variables : GRAFANA_PASSWORD (si le mot de passe admin a ete change), SANS_AGENT=1
set -euo pipefail
cd "$(dirname "$0")"; ICI=$(pwd)
set -a; . ./.env; set +a
ok() { echo "[OK] $1"; }; ko() { echo "[KO] $1"; exit 1; }

# --- Reperage des conteneurs Grafana et Prometheus (piles Docker Compose) ---
G=$(docker ps -q --filter label=com.docker.compose.service=grafana | head -1)
P=$(docker ps -q --filter label=com.docker.compose.service=prometheus | head -1)
[ -n "$G" ] || ko "Aucun conteneur Grafana (service compose 'grafana') en marche"
[ -n "$P" ] || ko "Aucun conteneur Prometheus (service compose 'prometheus') en marche"
lbl() { docker inspect -f "{{index .Config.Labels \"$2\"}}" "$1"; }
DIR=$(lbl "$P" com.docker.compose.project.working_dir)
PROJ=$(lbl "$P" com.docker.compose.project)
[ "$(lbl "$G" com.docker.compose.project)" = "$PROJ" ] || ko "Grafana et Prometheus ne sont pas dans la meme pile compose"
PROM_YML=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/etc/prometheus/prometheus.yml"}}{{.Source}}{{end}}{{end}}' "$P")
[ -f "$PROM_YML" ] || ko "Fichier prometheus.yml introuvable (monte sur /etc/prometheus/prometheus.yml)"
ok "Pile de supervision : $PROJ ($DIR)"

# --- 1. Reseau Wazuh + fichier d'alertes, par un docker-compose.override.yml de la pile de supervision ---
cp supervision/alertes-bcm.yml "$(dirname "$PROM_YML")/alertes-bcm.yml"
OVR="$DIR/docker-compose.override.yml"
if [ -f "$OVR" ] && ! grep -q 'wazuh_default' "$OVR"; then
  ko "$OVR existe deja : y ajouter le reseau externe wazuh_default pour grafana et prometheus (voir README)"
fi
cat > "$OVR" <<YML
# Ajoute par pile-wazuh/integrer-supervision.sh : acces de Grafana et Prometheus a la pile Wazuh
services:
  grafana:
    networks: [default, wazuh]
  prometheus:
    networks: [default, wazuh]
    volumes:
      - $(dirname "$PROM_YML")/alertes-bcm.yml:/etc/prometheus/alertes-bcm.yml:ro
networks:
  wazuh:
    external: true
    name: wazuh_default
YML
ok "Reseau wazuh_default ajoute a Grafana et Prometheus ($OVR)"

# --- 2. Configuration Prometheus : exporteur + fichier d'alertes (sauvegarde avant modification) ---
cp "$PROM_YML" "$PROM_YML.avant-wazuh.$(date +%Y%m%d%H%M%S)"
python3 - "$PROM_YML" <<'PY'
import re, sys
p = sys.argv[1]; lines = open(p).read().splitlines()
def item_indent(i):
    for l in lines[i+1:]:
        if l.strip().startswith("-"):
            return l[:len(l) - len(l.lstrip())]
        if l and not l.startswith(" "):
            break
    return "  "
txt = "\n".join(lines)
if "alertes-bcm.yml" not in txt:
    idx = next((i for i, l in enumerate(lines) if l.startswith("rule_files:")), None)
    if idx is None:
        idx = next(i for i, l in enumerate(lines) if l.startswith("scrape_configs:"))
        lines[idx:idx] = ["rule_files:", "  - /etc/prometheus/alertes-bcm.yml", ""]
    else:
        lines.insert(idx + 1, item_indent(idx) + "- /etc/prometheus/alertes-bcm.yml")
if "job_name: bcm-exporteur" not in txt:
    idx = next(i for i, l in enumerate(lines) if l.startswith("scrape_configs:"))
    ind = item_indent(idx)
    lines[idx+1:idx+1] = [ind + "- job_name: bcm-exporteur",
                          ind + "  static_configs: [ { targets: [\"exporteur:9300\"] } ]"]
open(p, "w").write("\n".join(lines) + "\n")
PY
( cd "$DIR" && docker compose -p "$PROJ" up -d --no-deps grafana prometheus >/dev/null 2>&1 ) \
  || ko "Recreation de grafana/prometheus impossible : cd $DIR && docker compose up -d grafana prometheus"
P=$(docker ps -q --filter label=com.docker.compose.service=prometheus --filter label=com.docker.compose.project="$PROJ" | head -1)
G=$(docker ps -q --filter label=com.docker.compose.service=grafana --filter label=com.docker.compose.project="$PROJ" | head -1)
docker exec "$P" promtool check config /etc/prometheus/prometheus.yml >/dev/null 2>&1 \
  || ko "prometheus.yml invalide : restaurer la sauvegarde $PROM_YML.avant-wazuh.*"
for i in $(seq 1 12); do
  docker exec "$P" wget -qO- 'http://localhost:9090/api/v1/targets?state=active' 2>/dev/null \
    | grep -q '"job":"bcm-exporteur".*"health":"up"\|"health":"up".*"job":"bcm-exporteur"' && break; sleep 5
done
docker exec "$P" wget -qO- 'http://localhost:9090/api/v1/rules' 2>/dev/null | grep -q ConteneurArrete \
  && ok "Prometheus : exporteur collecte, 9 alertes chargees" || ko "Prometheus : alertes non chargees"

# --- 3. Grafana : source Wazuh et tableaux de bord (API) ---
GPASS=${GRAFANA_PASSWORD:-$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$G" | sed -n 's/^GF_SECURITY_ADMIN_PASSWORD=//p')}
GPORT=$(docker port "$G" 3000/tcp | head -1 | sed 's/0.0.0.0/127.0.0.1/')
GURL="http://${GPORT:-127.0.0.1:3000}"
for i in $(seq 1 24); do curl -sf "$GURL/api/health" >/dev/null && break; sleep 5; done
gapi() { curl -s -u "admin:${GPASS}" -H 'Content-Type: application/json' "$@"; }
gapi "$GURL/api/org" | grep -q '"id"' || ko "Connexion a Grafana refusee : relancer avec GRAFANA_PASSWORD=<mot de passe admin>"

DS=$(GRAFANA_INDEXER_PASSWORD="$GRAFANA_INDEXER_PASSWORD" python3 -c 'import json,os;print(json.dumps({
 "name":"Wazuh (alertes)","uid":"wazuh-alertes","type":"elasticsearch","access":"proxy",
 "url":"https://wazuh.indexer:9200","basicAuth":True,"basicAuthUser":"grafana",
 "secureJsonData":{"basicAuthPassword":os.environ["GRAFANA_INDEXER_PASSWORD"]},
 "jsonData":{"index":"wazuh-alerts-*","timeField":"timestamp","tlsSkipVerify":True,
  "logMessageField":"full_log","logLevelField":"rule.level","maxConcurrentShardRequests":5}}))')
if gapi "$GURL/api/datasources/uid/wazuh-alertes" | grep -q '"uid":"wazuh-alertes"'; then
  echo "$DS" | gapi -X PUT "$GURL/api/datasources/uid/wazuh-alertes" -d @- >/dev/null
else
  echo "$DS" | gapi -X POST "$GURL/api/datasources" -d @- >/dev/null
fi
gapi "$GURL/api/datasources/uid/wazuh-alertes/health" | grep -q '"status":"OK"' \
  && ok "Grafana : source 'Wazuh (alertes)' connectee a l'indexer" || ko "Grafana : source Wazuh en erreur"

PROM_UID=$(gapi "$GURL/api/datasources" | python3 -c 'import json,sys;print(next((d["uid"] for d in json.load(sys.stdin) if d["type"]=="prometheus"),""))')
[ -n "$PROM_UID" ] || ko "Grafana : aucune source Prometheus"
gapi -X POST "$GURL/api/folders" -d '{"uid":"supervision-bcm","title":"Supervision BCM"}' >/dev/null || true
for f in supervision/grafana/*.json; do
  python3 - "$f" "$PROM_UID" <<'PY' | gapi -X POST "$GURL/api/dashboards/db" -d @- | grep -q '"status":"success"' \
    && ok "Grafana : tableau $(basename "$f" .json) importe" || ko "Grafana : import de $f"
import json, sys
d = json.load(open(sys.argv[1])); s = json.dumps(d).replace("__PROM_UID__", sys.argv[2])
print(json.dumps({"dashboard": json.loads(s), "folderUid": "supervision-bcm", "overwrite": True}))
PY
done

# --- 4. Agent Wazuh sur ce serveur (journaux systeme, Docker/Tyk, integrite de la pile de supervision) ---
if [ "${SANS_AGENT:-0}" != "1" ]; then
  if ! systemctl is-active --quiet wazuh-agent 2>/dev/null; then
    sudo bash agents/install-agent-linux.sh 127.0.0.1 "$ENROLLMENT_PASSWORD" gateway
  fi
  # surveillance de la configuration de la pile de supervision (Tyk, Prometheus, Grafana)
  sed "s#</syscheck>#  <directories realtime=\"yes\" check_all=\"yes\" report_changes=\"yes\">$DIR</directories>\n  </syscheck>#" \
    agents/groupes/gateway/agent.conf > /tmp/agent.conf.bcm
  docker compose cp /tmp/agent.conf.bcm wazuh.manager:/var/ossec/etc/shared/gateway/agent.conf >/dev/null
  docker compose exec -T wazuh.manager chown wazuh:wazuh /var/ossec/etc/shared/gateway/agent.conf
  rm -f /tmp/agent.conf.bcm
  ok "Agent Wazuh de ce serveur : groupe gateway, surveillance de $DIR"
fi

echo
echo "Integration terminee. Grafana (tunnel SSH : ssh -L 3000:localhost:3000 ...) > Dashboards > Supervision BCM"
echo "Alertes Prometheus : http://localhost:9090/alerts (tunnel SSH -L 9090:localhost:9090)"
