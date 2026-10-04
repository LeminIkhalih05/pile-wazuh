# Pile Wazuh (SIEM) pour vm-siem — Projet BCM

Wazuh 4.14.8 en conteneurs Docker, mode **single-node** : manager, indexer et tableau de bord sur la même VM.
Basée sur le dépôt officiel `wazuh/wazuh-docker` (single-node), adaptée au projet :
secrets générés dans `.env`, comptes de démonstration supprimés, enrôlement des agents protégé par mot de passe,
API et indexer accessibles uniquement en local, réception syslog du réseau 192.168.12.0/24,
groupe d'agents `gateway` qui surveille la configuration de Tyk.

| Élément | Valeur |
|---|---|
| VM | vm-siem (ID 101), 192.168.12.103, Ubuntu 24.04 |
| Ressources | 6 vCPU, 16 Go de RAM, 300 Go de disque (guide « Supervision, sécurité et sauvegarde ») |
| Dossier | `/opt/wazuh` |
| Tableau de bord | https://192.168.12.103 (compte `admin`) |

## Installation en une commande

Sur un serveur Ubuntu / Debian neuf (VM Proxmox ou VM cloud), avec un compte qui a `sudo` :

```bash
curl -fsSL https://raw.githubusercontent.com/LeminIkhalih05/pile-wazuh/main/install.sh | bash
```

Le script installe Docker si besoin, clone le dépôt dans `~/pile-wazuh`, règle la mémoire de l'indexer
selon la RAM (`INDEXER_HEAP=2g` devant `bash` pour l'imposer), puis lance `setup.sh`.
Les mots de passe générés sont dans `~/pile-wazuh/.env`. Pour un dépôt privé, cloner à la main puis lancer `./install.sh`.

Le tableau de bord écoute sur le port 443, ou sur **8443** si 443 est déjà utilisé sur le serveur
(choix automatique, visible dans `.env` : `DASHBOARD_PORT`).

Sur une VM cloud (GCP…), ouvrir dans le pare-feu du fournisseur le port du tableau de bord (443 ou 8443) pour votre seule IP
(et 1514-1515 pour les IP des agents), jamais 9200 ni 55000.

## Contenu

| Fichier | Rôle |
|---|---|
| `docker-compose.yml` | Les trois conteneurs Wazuh |
| `.env.example` | Version, fuseau, mémoire de l'indexer, mots de passe (vides, générés par `setup.sh`) |
| `integrer-supervision.sh` | Liaison avec Prometheus et Grafana (exporteur, alertes, tableaux de bord, agent local) |
| `verifier.sh` | État de tous les services du serveur |
| `supervision/` | Exporteur Prometheus, alertes Prometheus, tableaux de bord Grafana |
| `install.sh` | Installation en une commande depuis GitHub (Docker, clonage, `setup.sh`) |
| `setup.sh` | Préparation et démarrage de la pile dans le dossier courant |
| `test.sh` | Contrôle de bon fonctionnement |
| `install-docker.sh` | Installation de Docker (script officiel) |
| `generer-certs.sh` | Certificats internes (openssl, sans accès Internet) |
| `config/` | Configuration du manager, de l'indexer et du tableau de bord |
| `agents/install-agent-linux.sh` | Installation et enrôlement d'un agent Linux |
| `agents/groupes/gateway/agent.conf` | Règles poussées à vm-gateway (intégrité des fichiers Tyk, journaux Docker) |

## 1. Préparer la VM

La VM 101 contient déjà une installation de Wazuh. Si elle tourne encore, l'arrêter avant
(les ports 443, 1514 et 1515 doivent être libres) et faire une sauvegarde Veeam de la VM.

```bash
# sur SRV1
qm set 101 --name vm-siem --cores 6 --memory 16384 --onboot 1 --tags siem
# dans la VM
sudo timedatectl set-timezone Africa/Nouakchott
sudo mkdir -p /opt/wazuh && sudo chown sysadmin: /opt/wazuh
```

Copier le contenu de ce dossier dans `/opt/wazuh` (par `scp` depuis le poste d'administration) :

```bash
scp -r pile-wazuh/. sysadmin@192.168.12.103:/opt/wazuh/
```

## 2. Installer et démarrer

```bash
cd /opt/wazuh
chmod +x *.sh agents/*.sh
./install-docker.sh        # si Docker n'est pas installé, puis se déconnecter / reconnecter
./setup.sh
```

`setup.sh` fait tout, dans l'ordre :

1. règle `vm.max_map_count=262144` (exigé par l'indexer, rendu permanent) ;
2. crée `.env` et génère les quatre mots de passe ;
3. calcule leurs empreintes bcrypt et crée `internal_users.yml` et `wazuh.yml` ;
4. génère les certificats internes avec openssl (autorité locale BCM, validité 10 ans) ;
5. démarre les conteneurs ;
6. crée le groupe `gateway` et active le mot de passe d'enrôlement ;
7. lance `test.sh`.

Résultat attendu (le premier démarrage prend 2 à 3 minutes) :

```
[OK] conteneur wazuh.manager demarre
[OK] conteneur wazuh.indexer demarre
[OK] conteneur wazuh.dashboard demarre
[OK] indexer : etat green
[OK] API Wazuh : authentification wazuh-wui
[OK] tableau de bord : HTTPS 302
[OK] port agents 1514 ouvert
[OK] port agents 1515 ouvert
```

**Copier aussitôt le fichier `.env` dans le coffre à mots de passe.** Il contient :

| Variable | Usage |
|---|---|
| `INDEXER_ADMIN_PASSWORD` | Connexion au tableau de bord avec le compte `admin` |
| `DASHBOARD_PASSWORD` | Compte technique `kibanaserver` (interne) |
| `API_PASSWORD` | Compte `wazuh-wui` de l'API Wazuh (interne) |
| `ENROLLMENT_PASSWORD` | Enrôlement des agents |

Mettre aussi au coffre la clé de l'autorité `config/wazuh_indexer_ssl_certs/root-ca.key`, puis la retirer du serveur
(`sudo rm`) : elle ne sert qu'à émettre de nouveaux certificats.

Accès Internet nécessaire pendant l'installation : Docker Hub (images Wazuh) sur vm-siem,
et `packages.wazuh.com` sur chaque machine qui reçoit un agent.
En fonctionnement, le manager télécharge la base des vulnérabilités sur `cti.wazuh.com` (HTTPS sortant).

## 3. Pare-feu de vm-siem

```bash
sudo ufw default deny incoming
sudo ufw allow from <RESEAU_ADMIN> to any port 22,443 proto tcp        # SSH et tableau de bord
sudo ufw allow from 192.168.12.0/24 to any port 1514,1515 proto tcp    # agents
sudo ufw allow from 192.168.12.0/24 to any port 514 proto udp          # syslog
sudo ufw allow from 192.168.12.150 to any port 9100 proto tcp          # node-exporter (Prometheus)
sudo ufw enable
```

Attention : Docker publie ses ports en contournant ufw. Les ports 9200 (indexer) et 55000 (API) sont
donc liés à `127.0.0.1` dans `docker-compose.yml` ; seuls 443, 1514, 1515 et 514/udp sont exposés.
Pour restreindre aussi ceux-là au réseau d'administration, filtrer dans la chaîne `DOCKER-USER`
ou sur le pare-feu Proxmox de la VM 101 (recommandé).

## 4. Installer les agents

Copier `agents/install-agent-linux.sh` sur chaque VM, puis :

```bash
# vm-gateway : groupe gateway (intégrité des fichiers Tyk + journaux des conteneurs)
sudo ./install-agent-linux.sh 192.168.12.103 '<ENROLLMENT_PASSWORD>' gateway

# vm-api, vm-data, vm-monitoring, mini-PC
sudo ./install-agent-linux.sh 192.168.12.103 '<ENROLLMENT_PASSWORD>'
```

Le script installe l'agent de la même version que le manager (4.14.8) et le bloque (`apt-mark hold`) :
un agent ne doit jamais être plus récent que le manager.

**vm-backup (Windows / Veeam)**, dans PowerShell administrateur :

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.8-1.msi -OutFile $env:TEMP\wazuh-agent.msi
msiexec.exe /i $env:TEMP\wazuh-agent.msi /q WAZUH_MANAGER="192.168.12.103" WAZUH_REGISTRATION_PASSWORD="<ENROLLMENT_PASSWORD>" WAZUH_AGENT_NAME="vm-backup"
NET START WazuhSvc
```

Dans le tableau de bord (**Agents management > Summary**), chaque machine doit être **Active**.
Si vm-gateway n'apparaît pas dans le groupe `gateway` :

```bash
docker compose exec wazuh.manager /var/ossec/bin/agent_control -l                  # repérer son ID
docker compose exec wazuh.manager /var/ossec/bin/agent_groups -a -i <ID> -g gateway
```

### Ce que surveille le groupe `gateway`

Le fichier `agents/groupes/gateway/agent.conf` est poussé par le manager à vm-gateway :

- intégrité des fichiers en temps réel sur `/opt/tyk`, `/home/sysadmin/api-gateway-stack` et `/etc/docker`
  (modification d'une API, d'une policy, d'un certificat) ;
- journaux de tous les conteneurs Docker (Tyk Gateway, Tyk Pump, Redis).

Adapter les chemins à l'emplacement réel de la pile Tyk sur vm-gateway, puis pousser la nouvelle version :

```bash
cd /opt/wazuh
docker compose cp agents/groupes/gateway/agent.conf wazuh.manager:/var/ossec/etc/shared/gateway/agent.conf
docker compose exec wazuh.manager chown wazuh:wazuh /var/ossec/etc/shared/gateway/agent.conf
```

Les agents récupèrent la nouvelle configuration en quelques minutes.

## 5. Envoyer les journaux syslog (Proxmox, switch, iLO)

Le manager écoute en syslog sur 514/udp pour le réseau 192.168.12.0/24.

Sur SRV1 et SRV2 (Proxmox) :

```bash
apt install -y rsyslog     # absent par défaut sur Proxmox récent
echo '*.* @192.168.12.103:514' > /etc/rsyslog.d/90-wazuh.conf
systemctl restart rsyslog
```

Switch Cisco : `logging host 192.168.12.103` puis `logging trap informational`.
iLO : **Management > Remote Syslog**, serveur 192.168.12.103, port 514.

## 6. Supervision avec Prometheus et Grafana

Sur un serveur qui fait déjà tourner Prometheus et Grafana en Docker Compose (par exemple la pile
`pile-tyk-monitoring`), une commande relie tout :

```bash
cd ~/pile-wazuh && ./integrer-supervision.sh
```

Le script :

1. ajoute Grafana et Prometheus au réseau Docker de Wazuh, par un `docker-compose.override.yml`
   placé dans le dossier de leur pile (le lien survit aux redémarrages) ;
2. ajoute à `prometheus.yml` (sauvegarde `prometheus.yml.avant-wazuh.*`) la collecte de l'exporteur BCM
   et 9 alertes (`supervision/alertes-bcm.yml`) ;
3. crée dans Grafana la source **Wazuh (alertes)**, avec le compte `grafana` en lecture seule de l'indexer,
   et deux tableaux de bord dans le dossier **Supervision BCM** ;
4. installe un agent Wazuh sur le serveur (`SANS_AGENT=1` pour s'en passer) : journaux du système et des
   conteneurs Docker (dont Tyk), intégrité des fichiers de la pile de supervision.

Si le mot de passe admin de Grafana a été changé : `GRAFANA_PASSWORD='...' ./integrer-supervision.sh`.

| Élément | Contenu |
|---|---|
| Exporteur BCM (`exporteur:9300`) | État de chaque conteneur du serveur, redémarrages, agents Wazuh (actifs, déconnectés), alertes Wazuh par niveau sur 5 et 60 min |
| Tableau **Supervision – conteneurs et Wazuh** | Conteneurs en marche ou arrêtés, cibles Prometheus, agents, alertes par niveau |
| Tableau **Sécurité – alertes Wazuh** | Alertes par niveau dans le temps, règles et machines les plus concernées, accès refusés par Tyk, dernières alertes |
| Alertes Prometheus | Conteneur arrêté ou qui redémarre en boucle, Wazuh injoignable, agent déconnecté, alerte de sécurité de niveau 12+, disque et mémoire |
| Règles Wazuh BCM | Journaux Tyk : clé ou jeton JWT refusé, quota dépassé, erreur de la passerelle, rafale de refus (niveau 10) |

Accès (tunnel SSH depuis le poste) :

```bash
ssh -L 3000:localhost:3000 -L 9090:localhost:9090 -L 8443:localhost:8443 utilisateur@IP_DU_SERVEUR
```

Grafana : http://localhost:3000 (Dashboards > Supervision BCM) ; alertes Prometheus : http://localhost:9090/alerts ;
Wazuh : https://localhost:8443 (ou 443).

### Vérifier tous les services en une commande

```bash
~/pile-wazuh/verifier.sh
```

Affiche l'état de chaque conteneur, de la passerelle Tyk, des cibles et alertes Prometheus, de Grafana
et de Wazuh, puis `RESULTAT : tous les services sont operationnels` ou la liste des lignes `[KO]`.

## 7. Exploitation courante

| Action | Commande (dans `/opt/wazuh`) |
|---|---|
| État | `docker compose ps` puis `./test.sh` |
| Journaux | `docker compose logs -f wazuh.manager` (ou `wazuh.indexer`, `wazuh.dashboard`) |
| Redémarrer | `docker compose restart` |
| Arrêter / démarrer | `docker compose down` / `docker compose up -d` |
| Agents connectés | `docker compose exec wazuh.manager /var/ossec/bin/agent_control -l` |
| Supprimer un agent | `docker compose exec wazuh.manager /var/ossec/bin/manage_agents -r <ID>` |
| Espace disque | `docker system df -v \| grep wazuh` |

Les données sont dans des volumes Docker (`/var/lib/docker/volumes/wazuh_*`) : la sauvegarde Veeam
quotidienne de la VM les couvre. Ne jamais lancer `docker compose down -v` (efface toutes les alertes et
les clés des agents).

### Mise à jour de Wazuh

1. Sauvegarde Veeam de vm-siem.
2. Lire les notes de version de `wazuh-docker` pour la version cible (fichiers de configuration modifiés).
3. Changer `WAZUH_VERSION` dans `.env`, puis `docker compose pull && docker compose up -d`.
4. Mettre à jour les agents ensuite (`apt-mark unhold wazuh-agent`, installation de la même version, `apt-mark hold`).

### Changer un mot de passe après le premier démarrage

Modifier `.env` ne suffit pas : l'indexer a déjà enregistré les empreintes.
Suivre la procédure officielle « Changing the default password of Wazuh users » de la documentation
wazuh-docker de la version installée (empreinte avec `hash.sh`, mise à jour de `internal_users.yml`,
puis `securityadmin.sh` dans le conteneur indexer).
Pour le mot de passe d'enrôlement, il suffit de relancer la partie 6 de `setup.sh` :

```bash
set -a; . ./.env; set +a
docker compose exec -T -e P="$ENROLLMENT_PASSWORD" wazuh.manager sh -c 'printf "%s\n" "$P" > /var/ossec/etc/authd.pass'
docker compose restart wazuh.manager
```

### Réinstallation complète (efface toutes les données)

```bash
docker compose down -v
sudo rm -rf .env config/wazuh_indexer_ssl_certs config/wazuh_indexer/internal_users.yml config/wazuh_dashboard/wazuh.yml
./setup.sh
```

Les agents devront être enrôlés à nouveau.
