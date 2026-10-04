#!/usr/bin/env bash
# install-docker.sh : installe Docker et Compose (Ubuntu / Debian), script officiel de Docker
set -euo pipefail
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"
echo "Docker installe. Deconnectez-vous puis reconnectez-vous, puis lancez ./setup.sh"
