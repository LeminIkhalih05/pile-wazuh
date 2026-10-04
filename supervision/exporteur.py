#!/usr/bin/env python3
"""Exporteur Prometheus de la pile BCM (bibliotheque standard Python uniquement).

Expose sur :9300/metrics
  - l'etat de tous les conteneurs Docker du serveur (Tyk, Grafana, Prometheus, Wazuh...)
  - l'etat des agents Wazuh (API du manager)
  - le nombre d'alertes Wazuh par niveau sur les 5 et 60 dernieres minutes (indexer)
"""
import base64, http.client, json, os, socket, ssl, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API_URL = os.environ.get("WAZUH_API_HOST", "wazuh.manager")
API_USER, API_PASS = os.environ.get("API_USERNAME", "wazuh-wui"), os.environ.get("API_PASSWORD", "")
IDX_HOST = os.environ.get("INDEXER_HOST", "wazuh.indexer")
IDX_USER, IDX_PASS = os.environ.get("INDEXER_USERNAME", "grafana"), os.environ.get("INDEXER_PASSWORD", "")
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE


class DockerConn(http.client.HTTPConnection):
    def __init__(self):
        super().__init__("localhost", timeout=10)
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect("/var/run/docker.sock")


def get_json(conn, path, method="GET", headers=None, body=None):
    conn.request(method, path, body=body, headers=headers or {})
    r = conn.getresponse(); data = r.read()
    if r.status >= 300:
        raise RuntimeError(f"{path}: HTTP {r.status}")
    return json.loads(data)


def esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"')


def docker_metrics(out):
    ok = 1
    try:
        conts = get_json(DockerConn(), "/containers/json?all=1")
        for c in conts:
            name = c["Names"][0].lstrip("/")
            proj = c.get("Labels", {}).get("com.docker.compose.project", "")
            lbl = f'nom="{esc(name)}",projet="{esc(proj)}",image="{esc(c.get("Image", ""))}"'
            status = c.get("Status", "")
            out.append(f"bcm_conteneur_actif{{{lbl}}} {1 if c['State'] == 'running' else 0}")
            out.append(f"bcm_conteneur_sain{{{lbl}}} {0 if '(unhealthy)' in status else 1}")
            info = get_json(DockerConn(), f"/containers/{c['Id']}/json")
            out.append(f"bcm_conteneur_redemarrages{{{lbl}}} {info.get('RestartCount', 0)}")
            started = info.get("State", {}).get("StartedAt", "")[:19]
            if c["State"] == "running" and started:
                t = time.mktime(time.strptime(started, "%Y-%m-%dT%H:%M:%S")) - time.timezone
                out.append(f"bcm_conteneur_demarre_depuis_secondes{{{lbl}}} {int(time.time() - t)}")
    except Exception as e:
        ok = 0; print("docker:", e, flush=True)
    out.append(f'bcm_exporteur_source_ok{{source="docker"}} {ok}')


def wazuh_api_metrics(out):
    ok = 1
    try:
        conn = http.client.HTTPSConnection(API_URL, 55000, context=CTX, timeout=10)
        auth = base64.b64encode(f"{API_USER}:{API_PASS}".encode()).decode()
        conn.request("POST", "/security/user/authenticate?raw=true", headers={"Authorization": f"Basic {auth}"})
        r = conn.getresponse(); token = r.read().decode()
        if r.status != 200:
            raise RuntimeError(f"authentification API: HTTP {r.status}")
        summ = get_json(conn, "/agents/summary/status", headers={"Authorization": f"Bearer {token}"})
        conn_status = summ["data"]["connection"]
        for k in ("active", "disconnected", "pending", "never_connected"):
            out.append(f'bcm_wazuh_agents{{etat="{k}"}} {conn_status.get(k, 0)}')
    except Exception as e:
        ok = 0; print("api wazuh:", e, flush=True)
    out.append(f'bcm_exporteur_source_ok{{source="wazuh_api"}} {ok}')


def wazuh_alert_metrics(out):
    ok = 1
    try:
        conn = http.client.HTTPSConnection(IDX_HOST, 9200, context=CTX, timeout=10)
        auth = base64.b64encode(f"{IDX_USER}:{IDX_PASS}".encode()).decode()
        for minutes in (5, 60):
            body = json.dumps({"size": 0,
                               "query": {"range": {"timestamp": {"gte": f"now-{minutes}m"}}},
                               "aggs": {"n": {"range": {"field": "rule.level", "ranges": [
                                   {"key": "faible", "to": 7}, {"key": "moyen", "from": 7, "to": 12},
                                   {"key": "eleve", "from": 12}]}}}})
            res = get_json(conn, "/wazuh-alerts-*/_search", "POST",
                           {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}, body)
            # pas encore d'index d'alertes : compteurs a zero
            buckets = res.get("aggregations", {}).get("n", {}).get("buckets") or \
                [{"key": k, "doc_count": 0} for k in ("faible", "moyen", "eleve")]
            for b in buckets:
                out.append(f'bcm_wazuh_alertes{{niveau="{b["key"]}",fenetre="{minutes}m"}} {b["doc_count"]}')
    except Exception as e:
        ok = 0; print("indexer wazuh:", e, flush=True)
    out.append(f'bcm_exporteur_source_ok{{source="wazuh_indexer"}} {ok}')


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404); self.end_headers(); return
        out = []
        docker_metrics(out); wazuh_api_metrics(out); wazuh_alert_metrics(out)
        data = ("\n".join(out) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(data))); self.end_headers()
        self.wfile.write(data)
    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9300), Handler).serve_forever()
