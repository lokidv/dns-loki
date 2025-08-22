import os
import json
import threading
import re
import tempfile
import shutil
import zipfile
import subprocess
import time
from urllib.request import urlopen
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Request, Depends
from pydantic import BaseModel, IPvAnyAddress
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, StreamingResponse, JSONResponse
import io
import paramiko

DATA_DIR = os.environ.get("DATA_DIR", "/opt/dns-proxy/data")
DEFAULT_GIT_REPO = os.environ.get("DEFAULT_GIT_REPO", "")
DEFAULT_GIT_BRANCH = os.environ.get("DEFAULT_GIT_BRANCH", "main")
STATE_PATH = os.path.join(DATA_DIR, "state.json")
LOCK = threading.Lock()

app = FastAPI(title="DNS+SNI Control Plane")

# Serve simple UI if available
UI_DIR = os.path.join(os.path.dirname(__file__), "ui")
if os.path.isdir(UI_DIR):
    app.mount("/ui", StaticFiles(directory=UI_DIR, html=True), name="ui")

# ===== Internal Auth (Site ↔ Controller) =====
# If env INTERNAL_TOKEN is set, mutating endpoints must include a valid token via
# header 'X-Internal-Token: <token>' or 'Authorization: Bearer <token>'.
def _extract_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    if not auth_header:
        return None
    m = re.match(r"Bearer\s+(.+)", auth_header, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None

def require_internal(request: Request):
    expected = (os.environ.get("INTERNAL_TOKEN") or "").strip()
    # When not configured, treat as open (no auth enforced)
    if not expected:
        return
    token = request.headers.get("X-Internal-Token")
    if not token:
        token = _extract_bearer_token(request.headers.get("Authorization"))
    if token != expected:
        raise HTTPException(status_code=403, detail="forbidden")

# Global safeguard: enforce internal token on mutating requests by default
@app.middleware("http")
async def enforce_internal_token_mw(request: Request, call_next):
    expected = (os.environ.get("INTERNAL_TOKEN") or "").strip()
    method = request.method.upper()
    if expected and method in {"POST", "PUT", "PATCH", "DELETE"}:
        try:
            require_internal(request)
        except HTTPException as e:
            return JSONResponse(status_code=e.status_code, content={"detail": e.detail})
    return await call_next(request)

@app.get("/")
def root():
    if os.path.isdir(UI_DIR):
        return RedirectResponse(url="/ui/")
    return {"ok": True}

class Client(BaseModel):
    ip: IPvAnyAddress
    note: Optional[str] = None
    scope: List[str] = ["dns", "proxy"]

class Node(BaseModel):
    ip: IPvAnyAddress
    role: str  # dns|proxy
    enabled: bool = True
    agents_version_applied: Optional[int] = None
    ts: Optional[float] = None
    diag: Optional[dict] = None

class NodeIn(BaseModel):
    ip: Optional[IPvAnyAddress] = None
    role: str  # dns|proxy
    enabled: Optional[bool] = None
    agents_version_applied: Optional[int] = None
    ts: Optional[float] = None
    diag: Optional[dict] = None

class ConfigOut(BaseModel):
    clients: List[Client]
    nodes: List[Node]
    domains_version: int
    git_repo: str
    git_branch: str
    agents_version: int
    code_repo: str
    code_branch: str
    enforce_dns_clients: bool = True
    enforce_proxy_clients: bool = False

class DomainsPayload(BaseModel):
    domains: List[str]

class DomainItem(BaseModel):
    domain: str


class FlagsPayload(BaseModel):
    enforce_dns_clients: Optional[bool] = None
    enforce_proxy_clients: Optional[bool] = None


class ProvisionRequest(BaseModel):
    ip: str
    ssh_user: str
    ssh_password: Optional[str] = None
    ssh_key: Optional[str] = None
    install_docker: bool = True

class RestartRequest(BaseModel):
    ssh_user: str
    ssh_password: Optional[str] = None
    ssh_key: Optional[str] = None
    services: Optional[List[str]] = None  # e.g., ["agent", "coredns", "sniproxy"]


def _load_state():
    os.makedirs(DATA_DIR, exist_ok=True)
    # Try read existing state; tolerate corruption and rebuild with defaults
    st = None
    if os.path.exists(STATE_PATH):
        try:
            with open(STATE_PATH) as f:
                st = json.load(f)
        except Exception:
            st = None
    if not isinstance(st, dict):
        st = {
            "clients": [],
            "nodes": [],
            "domains_version": 1,
            "git_repo": DEFAULT_GIT_REPO,
            "git_branch": DEFAULT_GIT_BRANCH,
            "agents_version": 1,
            "code_repo": os.environ.get("CODE_REPO", "https://github.com/lokidv/dns-loki.git"),
            "code_branch": os.environ.get("CODE_BRANCH", "main"),
            "enforce_dns_clients": True,
            "enforce_proxy_clients": False,
            "domains": [],
        }
        with open(STATE_PATH, "w") as f:
            json.dump(st, f)
        return st
    # Ensure required keys exist (forward/backward compatibility)
    st.setdefault("clients", [])
    st.setdefault("nodes", [])
    st.setdefault("domains_version", 1)
    st.setdefault("git_repo", DEFAULT_GIT_REPO)
    st.setdefault("git_branch", DEFAULT_GIT_BRANCH)
    st.setdefault("agents_version", 1)
    st.setdefault("code_repo", os.environ.get("CODE_REPO", "https://github.com/lokidv/dns-loki.git"))
    st.setdefault("code_branch", os.environ.get("CODE_BRANCH", "main"))
    st.setdefault("enforce_dns_clients", True)
    st.setdefault("enforce_proxy_clients", False)
    st.setdefault("domains", [])
    _save_state(st)
    return st


def _save_state(st):
    with open(STATE_PATH, "w") as f:
        json.dump(st, f, indent=2)


@app.get("/v1/config", response_model=ConfigOut)
def get_config():
    with LOCK:
        st = _load_state()
        return st


@app.get("/v1/clients", response_model=List[Client])
def list_clients():
    with LOCK:
        st = _load_state()
        return st["clients"]


@app.post("/v1/clients", response_model=List[Client], dependencies=[Depends(require_internal)])
def add_client(c: Client):
    with LOCK:
        st = _load_state()
        if any(str(x["ip"]) == str(c.ip) for x in st["clients"]):
            return st["clients"]
        # Ensure JSON-serializable payload (ip as string)
        payload = json.loads(c.json())
        st["clients"].append(payload)
        _save_state(st)
        return st["clients"]


@app.delete("/v1/clients/{ip}", response_model=List[Client], dependencies=[Depends(require_internal)])
def del_client(ip: str):
    with LOCK:
        st = _load_state()
        st["clients"] = [x for x in st["clients"] if str(x["ip"]) != ip]
        _save_state(st)
        return st["clients"]


@app.get("/v1/flags")
def get_flags():
    with LOCK:
        st = _load_state()
        return {
            "enforce_dns_clients": bool(st.get("enforce_dns_clients", True)),
            "enforce_proxy_clients": bool(st.get("enforce_proxy_clients", False)),
        }


@app.post("/v1/flags", dependencies=[Depends(require_internal)])
def set_flags(f: FlagsPayload):
    with LOCK:
        st = _load_state()
        if f.enforce_dns_clients is not None:
            st["enforce_dns_clients"] = bool(f.enforce_dns_clients)
        if f.enforce_proxy_clients is not None:
            st["enforce_proxy_clients"] = bool(f.enforce_proxy_clients)
        _save_state(st)
        return {
            "enforce_dns_clients": st.get("enforce_dns_clients", True),
            "enforce_proxy_clients": st.get("enforce_proxy_clients", False),
        }


@app.get("/v1/nodes", response_model=List[Node])
def list_nodes():
    with LOCK:
        st = _load_state()
        return st["nodes"]


@app.post("/v1/nodes", response_model=List[Node], dependencies=[Depends(require_internal)])
def upsert_node(n: NodeIn, request: Request):
    with LOCK:
        st = _load_state()
        # Derive IP from payload or request if missing
        ip_str = str(n.ip) if n.ip is not None else request.client.host
        n_payload = {
            "ip": ip_str,
            "role": n.role,
            "agents_version_applied": n.agents_version_applied,
            "ts": n.ts,
            "diag": n.diag,
        }
        found = False
        for x in st["nodes"]:
            if str(x["ip"]) == ip_str:
                # Preserve existing values when incoming fields are None (avoid erasing)
                old_diag = x.get("diag")
                old_ver = x.get("agents_version_applied")
                x.update(n_payload)
                # Restore diag if missing in payload
                if x.get("diag") is None and old_diag is not None:
                    x["diag"] = old_diag
                # Do not let agents_version_applied decrease due to stale heartbeats
                incoming_ver = n_payload.get("agents_version_applied")
                if incoming_ver is None:
                    # keep previous when payload omits the field
                    if old_ver is not None:
                        x["agents_version_applied"] = old_ver
                else:
                    try:
                        old_i = int(old_ver) if old_ver is not None else 0
                    except Exception:
                        old_i = 0
                    try:
                        inc_i = int(incoming_ver)
                    except Exception:
                        inc_i = old_i
                    x["agents_version_applied"] = max(old_i, inc_i)
                found = True
        if not found:
            # Defaults for new node records to avoid nulls in UI/state
            if n_payload.get("agents_version_applied") is None:
                n_payload["agents_version_applied"] = 0
            if n_payload.get("diag") is None:
                n_payload["diag"] = {}
            # For a newly seen node, set enabled according to request if provided; otherwise default True
            if n.enabled is None:
                n_payload["enabled"] = True
            else:
                n_payload["enabled"] = bool(n.enabled)
            st["nodes"].append(n_payload)
        _save_state(st)
        return st["nodes"]


@app.post("/v1/nodes/{ip}/enable", response_model=List[Node], dependencies=[Depends(require_internal)])
def enable_node(ip: str):
    with LOCK:
        st = _load_state()
        for x in st["nodes"]:
            if str(x["ip"]) == ip:
                x["enabled"] = True
        _save_state(st)
        return st["nodes"]


@app.post("/v1/nodes/{ip}/disable", response_model=List[Node], dependencies=[Depends(require_internal)])
def disable_node(ip: str):
    with LOCK:
        st = _load_state()
        for x in st["nodes"]:
            if str(x["ip"]) == ip:
                x["enabled"] = False
        _save_state(st)
        return st["nodes"]


# ===== Proxy Provisioning (SSH) =====
@app.post("/v1/proxies/provision", dependencies=[Depends(require_internal)])
def provision_proxy(req: ProvisionRequest, request: Request):
    """Provision a remote host as Proxy node via SSH.
    Does NOT store credentials; executes a bootstrap script remotely.
    """
    if not (req.ssh_password or req.ssh_key):
        raise HTTPException(status_code=400, detail="Provide ssh_password or ssh_key")

    base_url = str(request.base_url).rstrip('/')

    with LOCK:
        st = _load_state()
        # Read code repo settings (used by remote to download initial code via controller archive)
        code_repo = st.get("code_repo") or "https://github.com/lokidv/dns-loki.git"
        code_branch = st.get("code_branch") or "main"

    log_lines = []

    def _log(s: str):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {s}"
        log_lines.append(line)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pkey = None
    if req.ssh_key:
        _log("loading SSH private key")
        try:
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(req.ssh_key))
        except Exception:
            try:
                pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(req.ssh_key))
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid ssh_key: {e}")

    try:
        _log(f"connecting to {req.ip} as {req.ssh_user}")
        client.connect(
            hostname=req.ip,
            username=req.ssh_user,
            password=req.ssh_password,
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
            raise HTTPException(status_code=500, detail=f"Remote provisioning failed with code {rc}")

        # Upsert node record optimistically
        with LOCK:
            st = _load_state()
            ip_str = req.ip
            exists = False
            for x in st["nodes"]:
                if str(x.get("ip")) == ip_str:
                    x["role"] = "proxy"
                    x["enabled"] = True
                    exists = True
    finally:
        try:
            client.close()
        except Exception:
            pass

@app.post("/v1/nodes/{ip}/restart", dependencies=[Depends(require_internal)])
def restart_node_services(ip: str, req: RestartRequest):
    """Restart one or more services on a remote node via SSH (agent, coredns, sniproxy).
    Does NOT store credentials; returns aggregated logs from remote execution.
    """
    if not (req.ssh_password or req.ssh_key):
        raise HTTPException(status_code=400, detail="Provide ssh_password or ssh_key")

    services = [s.strip().lower() for s in (req.services or ["agent", "coredns", "sniproxy"]) if s]
    services = [s for s in services if s in {"agent", "coredns", "sniproxy"}]
    if not services:
        raise HTTPException(status_code=400, detail="No valid services specified")

    log_lines: List[str] = []

    def _log(s: str):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        log_lines.append(f"[{ts}] {s}")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pkey = None
    if req.ssh_key:
        _log("loading SSH private key")
        try:
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(req.ssh_key))
        except Exception:
            try:
                pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(req.ssh_key))
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid ssh_key: {e}")

    try:
        _log(f"connecting to {ip} as {req.ssh_user}")
        client.connect(
            hostname=str(ip),
            username=req.ssh_user,
            password=req.ssh_password,
            pkey=pkey,
            allow_agent=False,
            look_for_keys=False,
            timeout=15,
        )
        sftp = client.open_sftp()
        try:
            svc_list = " ".join(services)
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
        # Do not fail hard to allow log visibility even if a service failed
    finally:
        try:
            client.close()
        except Exception:
            pass

    return {"ok": True, "services": services, "log": "\n".join(log_lines)}

@app.post("/v1/domains/sync", dependencies=[Depends(require_internal)])
def bump_domains_version():
    with LOCK:
        st = _load_state()
        st["domains_version"] = int(st.get("domains_version", 1)) + 1
        _save_state(st)
        return {"domains_version": st["domains_version"]}

# Domains CRUD API (store in controller state; Agent can consume directly if git_repo is empty)
@app.get("/v1/domains", response_model=List[str])
def get_domains():
    with LOCK:
        st = _load_state()
        return st.get("domains", [])

@app.post("/v1/domains", response_model=List[str], dependencies=[Depends(require_internal)])
def set_domains(payload: DomainsPayload):
    with LOCK:
        st = _load_state()
        # normalize and deduplicate
        items = []
        seen = set()
        for d in payload.domains:
            d = str(d).strip().lower()
            if not d:
                continue
            if d.startswith("*."):
                d = d[2:]
            if d not in seen:
                seen.add(d)
                items.append(d)
        st["domains"] = items
        st["domains_version"] = int(st.get("domains_version", 1)) + 1
        _save_state(st)
        return st["domains"]

@app.post("/v1/domains/add", response_model=List[str], dependencies=[Depends(require_internal)])
def add_domain(item: DomainItem):
    with LOCK:
        st = _load_state()
        d = str(item.domain).strip().lower()
        if d.startswith("*."):
            d = d[2:]
        if d and d not in st.get("domains", []):
            st["domains"].append(d)
            st["domains_version"] = int(st.get("domains_version", 1)) + 1
            _save_state(st)
        return st.get("domains", [])

@app.delete("/v1/domains/{domain}", response_model=List[str], dependencies=[Depends(require_internal)])
def delete_domain(domain: str):
    with LOCK:
        st = _load_state()
        d = str(domain).strip().lower()
        if d.startswith("*."):
            d = d[2:]
        st["domains"] = [x for x in st.get("domains", []) if x != d]
        st["domains_version"] = int(st.get("domains_version", 1)) + 1
        _save_state(st)
        return st.get("domains", [])

 # Note: duplicate /v1/flags endpoint removed (see earlier FlagsPayload + set_flags)

# Optional: set git_repo and git_branch via API
class GitSettings(BaseModel):
    git_repo: Optional[str] = None
    git_branch: Optional[str] = None


@app.post("/v1/git", dependencies=[Depends(require_internal)])
def set_git(settings: GitSettings):
    with LOCK:
        st = _load_state()
        if settings.git_repo is not None:
            st["git_repo"] = settings.git_repo
        if settings.git_branch is not None:
            st["git_branch"] = settings.git_branch
        _save_state(st)
        return {"git_repo": st["git_repo"], "git_branch": st["git_branch"]}

# ===== Code update management =====
class CodeSettings(BaseModel):
    code_repo: Optional[str] = None
    code_branch: Optional[str] = None

class AgentsVersionPayload(BaseModel):
    agents_version: Optional[int] = None
    code_repo: Optional[str] = None
    code_branch: Optional[str] = None


def _github_zip_url(repo_url: str, branch: str) -> Optional[str]:
    # پشتیبانی از حالت‌های متداول URL گیت‌هاب:
    # - https://github.com/owner/repo.git
    # - https://github.com/owner/repo
    # - http://github.com/owner/repo(.git)
    # - git@github.com:owner/repo(.git)
    if not repo_url:
        return None
    s = repo_url.strip()
    # تطبیق حالت SSH مانند git@github.com:owner/repo(.git)
    m_ssh = re.match(r"git@github\.com:([^/]+)/([^/]+)(?:\.git)?$", s)
    if m_ssh:
        owner, repo = m_ssh.group(1), m_ssh.group(2)
        return f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"

    # تطبیق حالت‌های http/https با/بدون www و با/بدون .git
    m_http = re.search(r"(?:https?://)?(?:www\.)?github\.com/([^/]+)/([^/]+)", s)
    if not m_http:
        return None
    owner, repo = m_http.group(1), m_http.group(2)
    repo = repo[:-4] if repo.endswith('.git') else repo
    return f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"


def _copy_tree(src: str, dst: str):
    os.makedirs(dst, exist_ok=True)
    for root, dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        target_root = os.path.join(dst, rel) if rel != "." else dst
        os.makedirs(target_root, exist_ok=True)
        for f in files:
            shutil.copy2(os.path.join(root, f), os.path.join(target_root, f))


@app.post("/v1/code", dependencies=[Depends(require_internal)])
def set_code_repo(settings: CodeSettings):
    with LOCK:
        st = _load_state()
        if settings.code_repo is not None:
            st["code_repo"] = settings.code_repo
        if settings.code_branch is not None:
            st["code_branch"] = settings.code_branch
        _save_state(st)
        return {"code_repo": st["code_repo"], "code_branch": st["code_branch"]}


@app.post("/v1/nodes/update", dependencies=[Depends(require_internal)])
def update_nodes(settings: CodeSettings = None):
    with LOCK:
        st = _load_state()
        if settings and settings.code_repo is not None:
            st["code_repo"] = settings.code_repo
        if settings and settings.code_branch is not None:
            st["code_branch"] = settings.code_branch
        # Bump applied version for all nodes by 1 (do not change target agents_version)
        updated = 0
        for node in st.get("nodes", []):
            cur = node.get("agents_version_applied")
            try:
                cur_i = int(cur) if cur is not None else 0
            except Exception:
                cur_i = 0
            node["agents_version_applied"] = cur_i + 1
            updated += 1
        _save_state(st)
        return {
            "updated_nodes": updated,
            "agents_version": st.get("agents_version", 1),
            "code_repo": st["code_repo"],
            "code_branch": st["code_branch"],
        }


@app.post("/v1/nodes/version", dependencies=[Depends(require_internal)])
def set_agents_version(payload: AgentsVersionPayload):
    """Set the agents_version explicitly (or bump by 1 if not provided).
    Optionally update code_repo/code_branch alongside.
    """
    with LOCK:
        st = _load_state()
        if payload and payload.code_repo is not None:
            st["code_repo"] = payload.code_repo
        if payload and payload.code_branch is not None:
            st["code_branch"] = payload.code_branch
        if payload and payload.agents_version is not None:
            try:
                st["agents_version"] = int(payload.agents_version)
            except Exception:
                raise HTTPException(status_code=400, detail="invalid agents_version")
        else:
            st["agents_version"] = int(st.get("agents_version", 1)) + 1
        _save_state(st)
        return {"agents_version": st["agents_version"], "code_repo": st["code_repo"], "code_branch": st["code_branch"]}


@app.post("/v1/nodes/force-reset", dependencies=[Depends(require_internal)])
def force_reset_agents():
    """Force reset all agents by resetting their applied version to 0 and bumping target version.
    This will trigger a fresh sync cycle for all agents.
    """
    with LOCK:
        st = _load_state()
        # Reset all agents' applied version to 0
        for node in st["nodes"]:
            node["agents_version_applied"] = 0
        # Bump target version to force update
        st["agents_version"] = int(st.get("agents_version", 1)) + 1
        _save_state(st)
        return {
            "message": "All agents reset and target version bumped",
            "agents_version": st["agents_version"],
            "reset_nodes": len(st["nodes"])
        }


@app.post("/v1/code/self-update", dependencies=[Depends(require_internal)])
def self_update_controller():
    """Download latest code and update controller files and UI, then restart service in background."""
    with LOCK:
        st = _load_state()
        repo = st.get("code_repo") or "https://github.com/lokidv/dns-loki.git"
        branch = st.get("code_branch") or "main"

    url = _github_zip_url(repo, branch)
    if not url:
        raise HTTPException(status_code=400, detail="Unsupported repo URL (only GitHub is supported)")

    tmpdir = tempfile.mkdtemp(prefix="dns_loki_upd_")
    zip_path = os.path.join(tmpdir, "src.zip")
    try:
        with urlopen(url, timeout=30) as resp, open(zip_path, "wb") as f:
            shutil.copyfileobj(resp, f)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(tmpdir)
        # find extracted root (robust for any repo name)
        root = None
        for name in os.listdir(tmpdir):
            p = os.path.join(tmpdir, name)
            if os.path.isdir(p):
                # prefer a directory that contains controller/api.py
                if os.path.exists(os.path.join(p, "controller", "api.py")):
                    root = p
                    break
                if root is None:
                    root = p
        if not root:
            raise HTTPException(status_code=500, detail="Cannot locate extracted source root (zip format unexpected)")

        # copy controller files
        shutil.copy2(os.path.join(root, "controller", "api.py"), "/opt/dns-proxy/controller/api.py")
        if os.path.exists(os.path.join(root, "controller", "requirements.txt")):
            shutil.copy2(os.path.join(root, "controller", "requirements.txt"), "/opt/dns-proxy/controller/requirements.txt")
        # copy UI
        ui_src = os.path.join(root, "controller", "ui")
        if os.path.isdir(ui_src):
            if os.path.isdir("/opt/dns-proxy/controller/ui"):
                shutil.rmtree("/opt/dns-proxy/controller/ui")
            _copy_tree(ui_src, "/opt/dns-proxy/controller/ui")
        # upgrade controller deps
        try:
            subprocess.run([
                "/opt/dns-proxy/controller/venv/bin/pip", "install", "-r", "/opt/dns-proxy/controller/requirements.txt"
            ], check=False)
        except Exception:
            pass
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    # restart controller in background after short delay
    try:
        subprocess.Popen([
            "bash", "-lc", "sleep 1; systemctl restart dns-proxy-controller"
        ])
    except Exception:
        pass

    return {"ok": True, "restarting": True}


@app.get("/v1/code/archive")
def get_code_archive(repo: Optional[str] = None, branch: Optional[str] = None):
    """Stream zip archive of the desired repo/branch to agents.
    If repo/branch are not provided, use values from controller state.
    """
    with LOCK:
        st = _load_state()
        repo_url = repo or st.get("code_repo") or "https://github.com/lokidv/dns-loki.git"
        br = branch or st.get("code_branch") or "main"
    url = _github_zip_url(repo_url, br)
    if not url:
        raise HTTPException(status_code=400, detail="Unsupported repo URL (only GitHub is supported)")

    def _iter():
        try:
            with urlopen(url, timeout=45) as resp:
                while True:
                    chunk = resp.read(1024 * 64)
                    if not chunk:
                        break
                    yield chunk
        except Exception:
            # propagate as empty stream to client; they'll handle failure
            return

    headers = {"Content-Disposition": f"attachment; filename=code-{br}.zip"}
    return StreamingResponse(_iter(), media_type="application/zip", headers=headers)
