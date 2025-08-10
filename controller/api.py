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
            "agents_version": 1,
            "code_repo": os.environ.get("CODE_REPO", "https://github.com/lokidv/dns-loki.git"),
            "code_branch": os.environ.get("CODE_BRANCH", "main"),
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
    st.setdefault("agents_version", 1)
    st.setdefault("code_repo", os.environ.get("CODE_REPO", "https://github.com/lokidv/dns-loki.git"))
    st.setdefault("code_branch", os.environ.get("CODE_BRANCH", "main"))
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
                # Preserve existing values when incoming fields are None (avoid erasing)
                old_diag = x.get("diag")
                old_ver = x.get("agents_version_applied")
                x.update(n_payload)
                if x.get("diag") is None and old_diag is not None:
                    x["diag"] = old_diag
                if x.get("agents_version_applied") is None and old_ver is not None:
                    x["agents_version_applied"] = old_ver
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

# ===== Code update management =====
class CodeSettings(BaseModel):
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
        st["agents_version"] = int(st.get("agents_version", 1)) + 1
        _save_state(st)
        return {"agents_version": st["agents_version"], "code_repo": st["code_repo"], "code_branch": st["code_branch"]}


@app.post("/v1/code/self-update")
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
