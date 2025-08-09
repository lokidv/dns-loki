import os
import json
import threading
from typing import List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, IPvAnyAddress
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse

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

class ConfigOut(BaseModel):
    clients: List[Client]
    nodes: List[Node]
    domains_version: int
    git_repo: str
    git_branch: str
    enforce_dns_clients: bool = False
    enforce_proxy_clients: bool = False

class DomainsPayload(BaseModel):
    domains: List[str]

class DomainItem(BaseModel):
    domain: str


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
            "enforce_dns_clients": False,
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
    st.setdefault("enforce_dns_clients", False)
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


@app.get("/v1/nodes", response_model=List[Node])
def list_nodes():
    with LOCK:
        st = _load_state()
        return st["nodes"]


@app.post("/v1/nodes", response_model=List[Node])
def upsert_node(n: Node):
    with LOCK:
        st = _load_state()
        n_payload = json.loads(n.json())  # ensure ip is string for JSON persistence
        found = False
        for x in st["nodes"]:
            if str(x["ip"]) == str(n.ip):
                x.update(n_payload)
                found = True
        if not found:
            st["nodes"].append(n_payload)
        _save_state(st)
        return st["nodes"]


@app.post("/v1/nodes/{ip}/enable", response_model=List[Node])
def enable_node(ip: str):
    with LOCK:
        st = _load_state()
        for x in st["nodes"]:
            if str(x["ip"]) == ip:
                x["enabled"] = True
        _save_state(st)
        return st["nodes"]


@app.post("/v1/nodes/{ip}/disable", response_model=List[Node])
def disable_node(ip: str):
    with LOCK:
        st = _load_state()
        for x in st["nodes"]:
            if str(x["ip"]) == ip:
                x["enabled"] = False
        _save_state(st)
        return st["nodes"]


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

@app.post("/v1/domains/add", response_model=List[str])
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

@app.delete("/v1/domains/{domain}", response_model=List[str])
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


class Flags(BaseModel):
    enforce_dns_clients: Optional[bool] = None
    enforce_proxy_clients: Optional[bool] = None


@app.post("/v1/flags")
def set_flags(flags: Flags):
    with LOCK:
        st = _load_state()
        if flags.enforce_dns_clients is not None:
            st["enforce_dns_clients"] = bool(flags.enforce_dns_clients)
        if flags.enforce_proxy_clients is not None:
            st["enforce_proxy_clients"] = bool(flags.enforce_proxy_clients)
        _save_state(st)
        return {
            "enforce_dns_clients": st["enforce_dns_clients"],
            "enforce_proxy_clients": st["enforce_proxy_clients"],
        }

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
