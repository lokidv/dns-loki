#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Universal installer for DNS/Proxy nodes and Controller
# Usage examples:
#  - Controller: sudo ./scripts/install.sh --role controller --bind 0.0.0.0:8080
#  - DNS node:   sudo ./scripts/install.sh --role dns --controller-url http://<controller_ip>:8080 --git-repo <repo_url> --git-branch main
#  - Proxy node: sudo ./scripts/install.sh --role proxy --controller-url http://<controller_ip>:8080 --git-repo <repo_url> --git-branch main

ROLE=""
BIND="0.0.0.0:8080"
CONTROLLER_URL=""
GIT_REPO=""
GIT_BRANCH="main"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)
      ROLE="$2"; shift 2;;
    --bind)
      BIND="$2"; shift 2;;
    --controller-url)
      CONTROLLER_URL="$2"; shift 2;;
    --git-repo)
      GIT_REPO="$2"; shift 2;;
    --git-branch)
      GIT_BRANCH="$2"; shift 2;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

if [[ -z "$ROLE" ]]; then
  echo "--role is required (controller|dns|proxy)"; exit 1
fi

OS_ID="$(. /etc/os-release && echo "$ID")"
if [[ "$OS_ID" != "ubuntu" && "$OS_ID" != "debian" ]]; then
  echo "This installer currently supports Debian/Ubuntu family."; exit 1
fi

apt-get update -y
apt-get install -y curl git nftables python3 python3-venv python3-pip

# Docker
if ! command -v docker >/dev/null 2>&1; then
  apt-get install -y docker.io
  systemctl enable --now docker
fi
# Compose plugin
if ! docker compose version >/dev/null 2>&1; then
  if apt-get install -y docker-compose-plugin; then
    echo "Installed docker-compose-plugin from apt."
  else
    echo "docker-compose-plugin not available via apt; installing Compose v2 binary..."
    ARCH="$(uname -m)"
    case "$ARCH" in
      x86_64|amd64) BIN="docker-compose-linux-x86_64" ;;
      aarch64|arm64) BIN="docker-compose-linux-aarch64" ;;
      *) echo "Unsupported arch: $ARCH"; exit 1 ;;
    esac
    COMPOSE_VER="v2.27.0"
    mkdir -p /usr/libexec/docker/cli-plugins /usr/lib/docker/cli-plugins
    curl -fsSL "https://github.com/docker/compose/releases/download/${COMPOSE_VER}/${BIN}" -o /tmp/docker-compose
    install -m 0755 /tmp/docker-compose /usr/libexec/docker/cli-plugins/docker-compose
    install -m 0755 /tmp/docker-compose /usr/lib/docker/cli-plugins/docker-compose
    rm -f /tmp/docker-compose
  fi
fi

mkdir -p /opt/dns-proxy/{agent,controller,data,domains}
mkdir -p /opt/dns-proxy/docker/{dns,proxy}
mkdir -p /opt/dns-proxy/nftables

cp -f "${BASE_DIR}/agent/agent.py" /opt/dns-proxy/agent/
cp -f "${BASE_DIR}/agent/requirements.txt" /opt/dns-proxy/agent/
cp -f "${BASE_DIR}/controller/api.py" /opt/dns-proxy/controller/ || true
cp -f "${BASE_DIR}/controller/requirements.txt" /opt/dns-proxy/controller/ || true
cp -f "${BASE_DIR}/docker/dns/docker-compose.yml" /opt/dns-proxy/docker/dns/
cp -f "${BASE_DIR}/docker/dns/Corefile" /opt/dns-proxy/docker/dns/
cp -f "${BASE_DIR}/docker/proxy/docker-compose.yml" /opt/dns-proxy/docker/proxy/
cp -f "${BASE_DIR}/docker/proxy/sniproxy.conf.tmpl" /opt/dns-proxy/docker/proxy/
cp -f "${BASE_DIR}/nftables"/*.nft /opt/dns-proxy/nftables/ 2>/dev/null || true

# Agent config
cat >/opt/dns-proxy/agent/agent.yaml <<EOF
role: "$ROLE"          # controller|dns|proxy (agent only runs for dns/proxy)
controller_url: "${CONTROLLER_URL}"
git_repo: "${GIT_REPO}"
git_branch: "${GIT_BRANCH}"
work_dir: "/opt/dns-proxy"
health_check_interval_seconds: 10
# Enforcement toggles (set true later when ready to lock down)
enforce_dns_clients: false
enforce_proxy_clients: false
EOF

# Ensure nftables is enabled
systemctl enable --now nftables

if [[ "$ROLE" == "controller" ]]; then
  if [[ -z "$BIND" ]]; then echo "--bind required for controller"; exit 1; fi
  # Write controller env
  mkdir -p /opt/dns-proxy/controller
  cat >/opt/dns-proxy/controller/.env <<EOF
HOST=${BIND%:*}
PORT=${BIND#*:}
DATA_DIR=/opt/dns-proxy/data
DEFAULT_GIT_REPO=${GIT_REPO}
DEFAULT_GIT_BRANCH=${GIT_BRANCH}
EOF
  python3 -m venv /opt/dns-proxy/controller/venv
  /opt/dns-proxy/controller/venv/bin/pip install --upgrade pip
  /opt/dns-proxy/controller/venv/bin/pip install -r /opt/dns-proxy/controller/requirements.txt
  # Systemd service for controller
  cat >/etc/systemd/system/dns-proxy-controller.service <<'SVC'
[Unit]
Description=DNS+SNI Control Plane API
After=network-online.target
Wants=network-online.target

[Service]
User=root
EnvironmentFile=/opt/dns-proxy/controller/.env
WorkingDirectory=/opt/dns-proxy/controller
ExecStart=/opt/dns-proxy/controller/venv/bin/uvicorn api:app --host ${HOST} --port ${PORT}
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
SVC
  systemctl daemon-reload
  systemctl enable --now dns-proxy-controller.service
  echo "Controller installed and started on ${BIND}"
  exit 0
fi

# Create agent venv
python3 -m venv /opt/dns-proxy/agent/venv
/opt/dns-proxy/agent/venv/bin/pip install --upgrade pip
/opt/dns-proxy/agent/venv/bin/pip install -r /opt/dns-proxy/agent/requirements.txt

# Systemd for agent
cat >/etc/systemd/system/dns-proxy-agent.service <<'SVC'
[Unit]
Description=DNS+SNI Agent
After=network-online.target docker.service
Requires=docker.service

[Service]
User=root
WorkingDirectory=/opt/dns-proxy/agent
ExecStart=/opt/dns-proxy/agent/venv/bin/python /opt/dns-proxy/agent/agent.py --config /opt/dns-proxy/agent/agent.yaml
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
SVC
systemctl daemon-reload

if [[ "$ROLE" == "dns" ]]; then
  # Free port 53 by disabling systemd-resolved and set resolv.conf
  if systemctl is-active --quiet systemd-resolved; then
    systemctl disable --now systemd-resolved || true
    mv /etc/resolv.conf /etc/resolv.conf.backup 2>/dev/null || true
    cat >/etc/resolv.conf <<'RCF'
nameserver 1.1.1.1
nameserver 1.0.0.1
RCF
  fi
  # Prepare CoreDNS runtime files
  touch /opt/dns-proxy/docker/dns/targets.override
  touch /opt/dns-proxy/docker/dns/v6block.override
  # Bring up DNS stack
  (cd /opt/dns-proxy/docker/dns && docker compose up -d)
  # Apply base nft rules (non-enforcing by default)
  nft -f /opt/dns-proxy/nftables/dns.nft || true
  systemctl enable --now dns-proxy-agent.service
  echo "DNS node installed. Agent started."
  exit 0
fi

if [[ "$ROLE" == "proxy" ]]; then
  # Seed initial sniproxy.conf for amd.com so container can start
  if [[ ! -f /opt/dns-proxy/docker/proxy/sniproxy.conf ]]; then
    cat >/opt/dns-proxy/docker/proxy/sniproxy.conf <<'SNI'
user nobody
pidfile /var/run/sniproxy.pid
resolver {
  nameserver 1.1.1.1
  nameserver 1.0.0.1
}

listener 0.0.0.0:80 {
  proto http
  table {
    amd.com *
    .amd.com *
  }
}

listener 0.0.0.0:443 {
  proto tls
  table {
    amd.com *
    .amd.com *
  }
}
SNI
  fi
  # Bring up SNI proxy stack
  (cd /opt/dns-proxy/docker/proxy && docker compose up -d)
  # Apply base nft rules (non-enforcing by default) and block UDP/443
  nft -f /opt/dns-proxy/nftables/proxy.nft || true
  systemctl enable --now dns-proxy-agent.service
  echo "Proxy node installed. Agent started."
  exit 0
fi

echo "Unknown role: $ROLE"; exit 1
