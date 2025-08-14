from typing import List, Optional
import io
import time
import paramiko
from controller.core.exceptions import RemoteExecutionError


def restart_services(
    ip: str,
    ssh_user: str,
    ssh_password: Optional[str],
    ssh_key: Optional[str],
    services: Optional[List[str]],
) -> dict:
    """Restart one or more services on a remote node via SSH (agent, coredns, sniproxy).

    This is a direct extraction of the logic from controller/api.py, made reusable.
    """
    svc = [s.strip().lower() for s in (services or ["agent", "coredns", "sniproxy"]) if s]
    svc = [s for s in svc if s in {"agent", "coredns", "sniproxy"}]

    log_lines: List[str] = []

    def _log(s: str):
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
            hostname=str(ip),
            username=ssh_user,
            password=ssh_password,
            pkey=pkey,
            allow_agent=False,
            look_for_keys=False,
            timeout=15,
        )
        sftp = client.open_sftp()
        try:
            svc_list = " ".join(svc)
            script = f"""#!/usr/bin/env bash
set -u
echo "[+] requested services: {svc_list}"

SERVICES=({svc_list})

has_service() {{
  local x
  for x in "${{SERVICES[@]}}"; do [[ "$x" == "$1" ]] && return 0; done
  return 1
}}

ensure_docker() {{
  if command -v docker >/dev/null 2>&1; then
    sudo systemctl enable --now docker >/dev/null 2>&1 || true
    return 0
  fi
  echo "[+] installing Docker via get.docker.com fallback"
  curl -fsSL https://get.docker.com | sudo sh || true
  sudo systemctl enable --now docker >/dev/null 2>&1 || true
}}

restart_compose_service() {{
  local service="$1"
  local tried=0
  for f in \
    /opt/dns-proxy/docker/dns/docker-compose.yml \
    /opt/dns-proxy/docker/proxy/docker-compose.yml; do
    if [ -f "$f" ]; then
      tried=1
      echo "[+] docker compose up -d $service using $f"
      timeout 25s docker compose -f "$f" up -d "$service" >/dev/null 2>&1 || true
      echo "[+] docker compose restart $service using $f"
      timeout 20s docker compose -f "$f" restart "$service" >/dev/null 2>&1 || true
    fi
  done
  if [ "$tried" = "0" ]; then
    echo "[!] compose file not found for $service, trying 'docker restart'"
  fi
  timeout 15s docker restart "$service" >/dev/null 2>&1 || true
  docker ps --format '{{.Names}}\t{{.Status}}' | grep -E "^$service\b" || true
}}

if has_service agent; then
  echo "[+] restarting agent via systemd"
  sudo systemctl restart dns-proxy-agent || true
  sudo systemctl is-active dns-proxy-agent || true
fi

if has_service coredns || has_service sniproxy; then
  ensure_docker
fi

if has_service coredns; then
  echo "[+] restarting coredns (docker)"
  restart_compose_service coredns
fi

if has_service sniproxy; then
  echo "[+] restarting sniproxy (docker)"
  restart_compose_service sniproxy
fi

echo "[+] done"
"""
            _log("uploading restart script")
            with sftp.file("/tmp/restart_services.sh", "w") as f:
                f.write(script)
            sftp.chmod("/tmp/restart_services.sh", 0o755)
        finally:
            sftp.close()

        _log("executing restart script")
        stdin, stdout, stderr = client.exec_command("sudo /tmp/restart_services.sh")
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
            tail = "\n".join(log_lines[-20:])
            raise RemoteExecutionError(f"Remote restart failed with code {rc}\n{tail}")
    finally:
        try:
            client.close()
        except Exception:
            pass

    return {"ok": True, "services": svc, "log": "\n".join(log_lines)}
