import os
import json
import threading
from typing import List, Optional
from fastapi import FastAPI, Request
from pydantic import BaseModel, IPvAnyAddress
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, StreamingResponse
try:
    # When running as a proper package (e.g., uvicorn controller.api:app)
    from controller.core.exceptions import BadRequestError
    from controller.main import wire_routers
    from controller.services.domain_service import normalize_domains, normalize_domain
    from controller.services.code_update_service import perform_self_update, iter_codeload_zip
    from controller.services.git_service import github_zip_url
    from controller.services.nodes_service import (
        upsert_node_in_state,
        set_node_enabled,
        NodeInModel,
    )
except ImportError:
    # Fallback for flat-file installs (e.g., uvicorn api:app with files copied under /opt/dns-proxy/controller)
    from core.exceptions import BadRequestError
    from main import wire_routers
    from services.domain_service import normalize_domains, normalize_domain
    from services.code_update_service import perform_self_update, iter_codeload_zip
    from services.git_service import github_zip_url
    from services.nodes_service import (
        upsert_node_in_state,
        set_node_enabled,
        NodeInModel,
    )

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
wire_routers(app)

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


@app.post("/v1/clients", response_model=List[Client])
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


@app.delete("/v1/clients/{ip}", response_model=List[Client])
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


@app.post("/v1/flags")
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


@app.post("/v1/nodes", response_model=List[Node])
def upsert_node(n: NodeIn, request: Request):
    with LOCK:
        st = _load_state()
        payload = NodeInModel(
            ip=(str(n.ip) if n.ip is not None else None),
            role=n.role,
            enabled=n.enabled,
            agents_version_applied=n.agents_version_applied,
            ts=n.ts,
            diag=n.diag,
        )
        req_ip = request.client.host if getattr(request, "client", None) else None
        upsert_node_in_state(st, payload, req_ip or "0.0.0.0")
        _save_state(st)
        return st["nodes"]


@app.post("/v1/nodes/{ip}/enable", response_model=List[Node])
def enable_node(ip: str):
    with LOCK:
        st = _load_state()
        set_node_enabled(st, ip, True)
        _save_state(st)
        return st["nodes"]


@app.post("/v1/nodes/{ip}/disable", response_model=List[Node])
def disable_node(ip: str):
    with LOCK:
        st = _load_state()
        set_node_enabled(st, ip, False)
        _save_state(st)
        return st["nodes"]


# ===== Proxy Provisioning (SSH) =====
@app.post("/v1/proxies/provision")
def provision_proxy(req: ProvisionRequest, request: Request):
    """Provision a remote host as Proxy node via SSH (thin controller endpoint).
    Delegates to controller.services.provisioning_service and upserts node state.
    """
    base_url = str(request.base_url).rstrip('/')
    with LOCK:
        st = _load_state()
        code_repo = st.get("code_repo") or "https://github.com/lokidv/dns-loki.git"
        code_branch = st.get("code_branch") or "main"

    try:
        from controller.services.provisioning_service import provision_proxy as svc_provision
    except ImportError:
        from services.provisioning_service import provision_proxy as svc_provision

    res = svc_provision(
        ip=req.ip,
        ssh_user=req.ssh_user,
        ssh_password=req.ssh_password,
        ssh_key=req.ssh_key,
        base_url=base_url,
        code_repo=code_repo,
        code_branch=code_branch,
    )

    # Upsert node record optimistically as enabled proxy
    with LOCK:
        st = _load_state()
        payload = NodeInModel(ip=req.ip, role="proxy", enabled=True)
        upsert_node_in_state(st, payload, req.ip)
        _save_state(st)

    return res

@app.post("/v1/nodes/{ip}/restart")
def restart_node_services(ip: str, req: RestartRequest):
    """Restart one or more services on a remote node via SSH (agent, coredns, sniproxy).
    Does NOT store credentials; returns aggregated logs from remote execution.
    """
    if not (req.ssh_password or req.ssh_key):
        raise BadRequestError("Provide ssh_password or ssh_key")

    # Validate requested services (optional: also done in service)
    services = [s.strip().lower() for s in (req.services or ["agent", "coredns", "sniproxy"]) if s]
    services = [s for s in services if s in {"agent", "coredns", "sniproxy"}]
    if not services:
        raise BadRequestError("No valid services specified")

    # Delegate to service implementation
    try:
        from controller.services.ssh_service import restart_services  # local import avoids circular deps
    except ImportError:
        from services.ssh_service import restart_services  # flat-file fallback

    result = restart_services(
        ip=ip,
        ssh_user=req.ssh_user,
        ssh_password=req.ssh_password,
        ssh_key=req.ssh_key,
        services=services,
    )

    return result

@app.post("/v1/domains/sync")
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

@app.post("/v1/domains", response_model=List[str])
def set_domains(payload: DomainsPayload):
    with LOCK:
        st = _load_state()
        # normalize and deduplicate via service helper
        st["domains"] = normalize_domains(payload.domains)
        st["domains_version"] = int(st.get("domains_version", 1)) + 1
        _save_state(st)
        return st["domains"]

@app.post("/v1/domains/add", response_model=List[str])
def add_domain(item: DomainItem):
    with LOCK:
        st = _load_state()
        d = normalize_domain(item.domain)
        if d and d not in st.get("domains", []):
            st["domains"].append(d)
            st["domains_version"] = int(st.get("domains_version", 1)) + 1
            _save_state(st)
        return st.get("domains", [])

@app.delete("/v1/domains/{domain}", response_model=List[str])
def delete_domain(domain: str):
    with LOCK:
        st = _load_state()
        d = normalize_domain(domain)
        st["domains"] = [x for x in st.get("domains", []) if x != d]
        st["domains_version"] = int(st.get("domains_version", 1)) + 1
        _save_state(st)
        return st.get("domains", [])


# (duplicate /v1/flags block removed; original is defined earlier via FlagsPayload)

# Optional: set git_repo and git_branch via API
class GitSettings(BaseModel):
    git_repo: Optional[str] = None
    git_branch: Optional[str] = None


@app.post("/v1/git")
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
    return github_zip_url(repo_url, branch)


def _copy_tree(src: str, dst: str):
    copy_tree(src, dst)


@app.post("/v1/code")
def set_code_repo(settings: CodeSettings):
    with LOCK:
        st = _load_state()
        if settings.code_repo is not None:
            st["code_repo"] = settings.code_repo
        if settings.code_branch is not None:
            st["code_branch"] = settings.code_branch
        _save_state(st)
        return {"code_repo": st["code_repo"], "code_branch": st["code_branch"]}


@app.post("/v1/nodes/update")
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


@app.post("/v1/nodes/version")
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
                raise BadRequestError("invalid agents_version")
        else:
            st["agents_version"] = int(st.get("agents_version", 1)) + 1
        _save_state(st)
        return {"agents_version": st["agents_version"], "code_repo": st["code_repo"], "code_branch": st["code_branch"]}


@app.post("/v1/nodes/force-reset")
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


@app.post("/v1/code/self-update")
def self_update_controller():
    """Download latest code and update controller files and UI, then restart service in background."""
    with LOCK:
        st = _load_state()
        repo = st.get("code_repo") or "https://github.com/lokidv/dns-loki.git"
        branch = st.get("code_branch") or "main"
    return perform_self_update(repo, branch)


@app.get("/v1/code/archive")
def get_code_archive(repo: Optional[str] = None, branch: Optional[str] = None):
    """Stream zip archive of the desired repo/branch to agents.
    If repo/branch are not provided, use values from controller state.
    """
    with LOCK:
        st = _load_state()
        repo_url = repo or st.get("code_repo") or "https://github.com/lokidv/dns-loki.git"
        br = branch or st.get("code_branch") or "main"

    # Upfront input validation to avoid streaming errors
    if github_zip_url(repo_url, br) is None:
        raise BadRequestError("Unsupported repo URL (only GitHub is supported)")

    def _iter():
        try:
            for chunk in iter_codeload_zip(repo_url, br):
                yield chunk
        except Exception:
            # propagate as empty stream to client; they'll handle failure
            return

    headers = {"Content-Disposition": f"attachment; filename=code-{br}.zip"}
    return StreamingResponse(_iter(), media_type="application/zip", headers=headers)
