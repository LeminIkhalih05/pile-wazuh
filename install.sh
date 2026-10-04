#!/usr/bin/env bash
# install.sh : installation de la pile Wazuh en une seule commande (Ubuntu / Debian)
#   curl -fsSL https://raw.githubusercontent.com/LeminIkhalih05/pile-wazuh/main/install.sh | bash
# Variables optionnelles : REPO (compte/depot), BRANCH (main), DIR (~/pile-wazuh), INDEXER_HEAP (ex. 2g)
set -euo pipefail
REPO="${REPO:-LeminIkhalih05/pile-wazuh}"
BRANCH="${BRANCH:-main}"
DIR="${DIR:-$HOME/pile-wazuh}"

sudo apt-get update -q && sudo apt-get install -y -q git curl openssl python3

if ! command -v docker >/dev/null; then
  echo "[..] Installation de Docker"
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER"
fi

if [ -d "$DIR/.git" ]; then
  git -C "$DIR" pull -q
else
  git clone -q -b "$BRANCH" "https://github.com/${REPO}.git" "$DIR"
fi
cd "$DIR"
chmod +x *.sh agents/*.sh

# Memoire de l'indexer adaptee a la RAM si non precisee : environ un quart de la RAM, entre 1 et 8 Go
if [ ! -f .env ]; then
  cp .env.example .env
  RAM_GB=$(awk '/MemTotal/ {print int($2/1024/1024)}' /proc/meminfo)
  H=${INDEXER_HEAP:-$(( RAM_GB/4 < 1 ? 1 : (RAM_GB/4 > 8 ? 8 : RAM_GB/4) ))g}
  sed -i "s/^INDEXER_HEAP=.*/INDEXER_HEAP=${H}/" .env
  echo "[OK] Memoire de l'indexer : ${H} (RAM ${RAM_GB} Go)"
fi

# Lance setup.sh avec les droits Docker, meme juste apres l'ajout au groupe docker
if docker info >/dev/null 2>&1; then ./setup.sh; else sg docker -c ./setup.sh; fi
echo "Installation terminee dans $DIR. Mots de passe : $DIR/.env (a mettre au coffre)"
