from typing import Optional, List
import io
import time
import paramiko
from controller.core.exceptions import RemoteExecutionError


def provision_proxy(
    *,
    ip: str,
    ssh_user: str,
    ssh_password: Optional[str],
    ssh_key: Optional[str],
    base_url: str,
    code_repo: str,
    code_branch: str,
) -> dict:
    """Provision a remote host as Proxy node via SSH.

    Replicates the logic previously embedded in `controller/api.py`, but reusable.
    Returns a dict with ok and aggregated log.
    Raises ValueError for bad inputs and RemoteExecutionError for remote failures.
    """
    if not (ssh_password or ssh_key):
        raise ValueError("Provide ssh_password or ssh_key")

    log_lines: List[str] = []

    def _log(s: str) -> None:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        log_lines.append(f"[{ts}] {s}")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pkey = None
    if ssh_key:
        _log("loading SSH private key")
        try:
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(ssh_key))
        except Exception:
            try:
                pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(ssh_key))
            except Exception as e:
                raise ValueError(f"Invalid ssh_key: {e}")

    try:
        _log(f"connecting to {ip} as {ssh_user}")
        client.connect(
            hostname=ip,
            username=ssh_user,
            password=ssh_password,
            pkey=pkey,
            allow_agent=False,
            look_for_keys=False,
            timeout=15,
        )
        sftp = client.open_sftp()
        try:
            script = f"""#!/usr/bin/env bash
set -euo pipefail
CONTROLLER="{base_url}"
CODE_REPO="{code_repo}"
CODE_BRANCH="{code_branch}"
ROLE="proxy"

echo "[+] creating directories"
sudo mkdir -p /opt/dns-proxy/agent /opt/dns-proxy/docker/proxy /opt/dns-proxy/domains

echo "[+] installing prerequisites"
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo apt-get install -y python3 python3-venv curl unzip ca-certificates
  if {str(bool(True)).lower() if True else 'false'} && {str(bool(True)).lower()}; then
    sudo apt-get install -y docker.io docker-compose-plugin || true
  fi
  # Ensure docker service is running on apt-based systems
  # Try enabling docker if present; otherwise fallback to official install script
  if ! command -v docker >/dev/null 2>&1; then
    echo "[+] installing Docker via get.docker.com fallback"
    curl -fsSL https://get.docker.com | sudo sh
  fi
  sudo systemctl enable --now docker || true
  # Ensure docker compose availability (plugin or manual CLI plugin)
  if ! docker compose version >/dev/null 2>&1; then
    echo "[+] installing docker compose CLI plugin manually"
    sudo mkdir -p /usr/local/lib/docker/cli-plugins
    sudo curl -SL "https://github.com/docker/compose/releases/download/v2.27.0/docker-compose-linux-x86_64" -o /usr/local/lib/docker/cli-plugins/docker-compose
    sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
  fi
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y python3 python3-venv curl unzip ca-certificates
  sudo dnf install -y docker docker-compose || true
  sudo systemctl enable --now docker || true
  # Ensure docker compose availability; if missing, install CLI plugin manually
  if ! docker compose version >/dev/null 2>&1; then
    sudo mkdir -p /usr/local/lib/docker/cli-plugins
    sudo curl -SL "https://github.com/docker/compose/releases/download/v2.27.0/docker-compose-linux-x86_64" -o /usr/local/lib/docker/cli-plugins/docker-compose
    sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
  fi
else
  echo "Unsupported package manager; install python3, venv, docker manually" >&2
fi

echo "[+] verifying docker and compose versions"
docker --version || true
docker compose version || true

echo "[+] fetching initial code archive from controller"
TMPDIR=$(mktemp -d)
curl -L "$CONTROLLER/v1/code/archive" -o "$TMPDIR/src.zip"
unzip -q -o "$TMPDIR/src.zip" -d "$TMPDIR/src"
ROOT=$(dirname $(dirname $(find "$TMPDIR/src" -type f -name agent.py | head -n1)))
if [ -z "$ROOT" ] || [ ! -d "$ROOT" ]; then echo "could not locate source root" >&2; exit 1; fi

echo "[+] staging agent files and proxy docker files"
sudo cp -f "$ROOT/agent/agent.py" /opt/dns-proxy/agent/agent.py
if [ -f "$ROOT/agent/requirements.txt" ]; then sudo cp -f "$ROOT/agent/requirements.txt" /opt/dns-proxy/agent/requirements.txt; fi
if [ -f "$ROOT/docker/proxy/docker-compose.yml" ]; then sudo cp -f "$ROOT/docker/proxy/docker-compose.yml" /opt/dns-proxy/docker/proxy/docker-compose.yml; fi
if [ -f "$ROOT/docker/proxy/sniproxy.conf.tmpl" ]; then sudo cp -f "$ROOT/docker/proxy/sniproxy.conf.tmpl" /opt/dns-proxy/docker/proxy/sniproxy.conf.tmpl; fi

echo "[+] creating python venv and installing agent requirements"
sudo python3 -m venv /opt/dns-proxy/agent/venv
sudo /opt/dns-proxy/agent/venv/bin/pip install --upgrade pip
if [ -f /opt/dns-proxy/agent/requirements.txt ]; then sudo /opt/dns-proxy/agent/venv/bin/pip install -r /opt/dns-proxy/agent/requirements.txt; fi

echo "[+] writing agent config"
cat <<EOF | sudo tee /opt/dns-proxy/agent/config.yaml >/dev/null
role: "$ROLE"
controller_url: "$CONTROLLER"
EOF

echo "[+] installing systemd service"
cat <<'EOF' | sudo tee /etc/systemd/system/dns-proxy-agent.service >/dev/null
[Unit]
Description=DNS Loki Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/dns-proxy/agent/venv/bin/python /opt/dns-proxy/agent/agent.py --config /opt/dns-proxy/agent/config.yaml
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now dns-proxy-agent.service

echo "[+] done"
"""
            _log("uploading bootstrap script")
            with sftp.file("/tmp/provision_proxy.sh", "w") as f:
                f.write(script)
            sftp.chmod("/tmp/provision_proxy.sh", 0o755)
        finally:
            sftp.close()

        _log("executing bootstrap script")
        stdin, stdout, stderr = client.exec_command("sudo /tmp/provision_proxy.sh")
        out = stdout.read().decode()
        err = stderr.read().decode()
        rc = stdout.channel.recv_exit_status()
        if out:
            for line in out.splitlines():
                _log("REMOTE: " + line)
        if err:
            for line in err.splitlines():
                _log("REMOTE-ERR: " + line)
        if rc != 0:
            # include last lines of log for context
            tail = "\n".join(log_lines[-20:])
            raise RemoteExecutionError(f"Remote provisioning failed with code {rc}\n{tail}")
    finally:
        try:
            client.close()
        except Exception:
            pass

    return {"ok": True, "log": "\n".join(log_lines)}
