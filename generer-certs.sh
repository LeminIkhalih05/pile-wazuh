#!/usr/bin/env bash
# generer-certs.sh : certificats internes de la pile (autorite locale + manager, indexer, tableau de bord, admin)
# Fait avec openssl, sans telechargement : fonctionne aussi sur un serveur sans acces Internet.
# Validite 10 ans. Les noms (DN) doivent correspondre a config/wazuh_indexer/wazuh.indexer.yml.
set -euo pipefail
cd "$(dirname "$0")"
D=config/wazuh_indexer_ssl_certs
SUBJ="/C=MR/L=Nouakchott/O=BCM/OU=Wazuh"
DAYS=3650
[ -f "$D/root-ca.pem" ] && { echo "Certificats deja presents dans $D"; exit 0; }
mkdir -p "$D"; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$T/root-ca.key" 2>/dev/null
openssl req -x509 -new -key "$T/root-ca.key" -sha256 -days $DAYS -subj "$SUBJ/CN=Wazuh Root CA BCM" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$T/root-ca.pem"

cert() {  # cert <nom> [dns]
  local n=$1 dns=${2:-}
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/$n-key.pem" 2>/dev/null
  openssl req -new -key "$T/$n-key.pem" -subj "$SUBJ/CN=$n" -out "$T/$n.csr"
  {
    echo "basicConstraints=CA:FALSE"
    echo "keyUsage=critical,digitalSignature,keyEncipherment"
    echo "extendedKeyUsage=serverAuth,clientAuth"
    [ -n "$dns" ] && echo "subjectAltName=DNS:$dns,DNS:localhost,IP:127.0.0.1"
  } > "$T/$n.ext"
  openssl x509 -req -in "$T/$n.csr" -CA "$T/root-ca.pem" -CAkey "$T/root-ca.key" -CAcreateserial \
    -days $DAYS -sha256 -extfile "$T/$n.ext" -out "$T/$n.pem" 2>/dev/null
}
cert admin
cert wazuh.indexer wazuh.indexer
cert wazuh.manager wazuh.manager
cert wazuh.dashboard wazuh.dashboard

cp "$T"/*.pem "$T/root-ca.key" "$D/"
cp "$D/root-ca.pem" "$D/root-ca-manager.pem"
# proprietaires attendus par les images : 1000 = indexer / tableau de bord, 999 = manager
sudo chown 1000:1000 "$D"/*
sudo chown 999:999 "$D"/root-ca-manager.pem "$D"/wazuh.manager.pem "$D"/wazuh.manager-key.pem
sudo chown root:root "$D/root-ca.key"
sudo chmod 400 "$D"/*; sudo chmod 500 "$D"
echo "[OK] Certificats generes dans $D (cle de l'autorite : root-ca.key, a mettre au coffre puis retirer du serveur)"
