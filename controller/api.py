import os
import json
import threading
from typing import List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, IPvAnyAddress

DATA_DIR = os.environ.get("DATA_DIR", "/opt/dns-proxy/data")
DEFAULT_GIT_REPO = os.environ.get("DEFAULT_GIT_REPO", "")
DEFAULT_GIT_BRANCH = os.environ.get("DEFAULT_GIT_BRANCH", "main")
STATE_PATH = os.path.join(DATA_DIR, "state.json")
LOCK = threading.Lock()

app = FastAPI(title="DNS+SNI Control Plane")

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
        st["clients"].append(c.dict())
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
        found = False
        for x in st["nodes"]:
            if str(x["ip"]) == str(n.ip):
                x.update(n.dict())
                found = True
        if not found:
            st["nodes"].append(n.dict())
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
