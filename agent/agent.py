import argparse
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import time
import requests
import yaml
from pathlib import Path
import tempfile
import zipfile
from urllib.request import urlopen

DEF_CORE_DNS_DIR = "/opt/dns-proxy/docker/dns"
DEF_PROXY_DIR = "/opt/dns-proxy/docker/proxy"
WORK_DIR = "/opt/dns-proxy"
DOMAINS_DIR = f"{WORK_DIR}/domains"
LAST_VER_FILE = f"{WORK_DIR}/agent/last_agents_version"
LOG_FILE = f"{WORK_DIR}/agent/agent.log"


def run(cmd, check=True):
    # print("RUN:", cmd)
    return subprocess.run(cmd, shell=True, check=check, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def log(msg: str):
    try:
        Path(f"{WORK_DIR}/agent").mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        # never raise from logging
        pass


def _auth_headers(token: str):
    """Build authentication headers for controller calls using INTERNAL_TOKEN.
    Returns None if token empty to avoid sending extra headers.
    """
    tok = (token or "").strip()
    if not tok:
        return None
    return {
        "X-Internal-Token": tok,
        "Authorization": f"Bearer {tok}",
    }


def ensure_docker_running() -> bool:
    """اطمینان از آماده بودن Docker. اگر سرویس بالا نیست، تلاش برای start/enable.
    خروجی True یعنی docker قابل استفاده است.
    """
    try:
        res = run("docker version -f '{{.Server.Version}}'", check=False)
        if res.returncode == 0 and (res.stdout or b""):
            return True
    except Exception:
        pass
    # تلاش برای بالا آوردن سرویس
    log("docker: attempting to enable and start service")
    run("systemctl enable --now docker", check=False)
    time.sleep(1)
    res2 = run("docker version -f '{{.Server.Version}}'", check=False)
    ok = (res2.returncode == 0)
    log(f"docker: availability after start -> rc={res2.returncode}")
    return ok


def ensure_git_repo(repo_url: str, branch: str):
    Path(DOMAINS_DIR).mkdir(parents=True, exist_ok=True)
    if not (Path(DOMAINS_DIR) / ".git").exists():
        run(f"git clone -b {branch} {repo_url} {DOMAINS_DIR}")
    else:
        # ensure remote origin URL matches desired repo_url
        try:
            cur = subprocess.check_output(["git", "-C", DOMAINS_DIR, "remote", "get-url", "origin"], text=True).strip()
        except Exception:
            cur = ""
        if cur != repo_url:
            run(f"git -C {DOMAINS_DIR} remote set-url origin {repo_url}")
        run(f"git -C {DOMAINS_DIR} fetch --all")
        run(f"git -C {DOMAINS_DIR} reset --hard origin/{branch}")


def _github_zip_url(repo_url: str, branch: str):
    # پشتیبانی از حالت‌های HTTPS/SSH و انتهای .git مشابه کنترلر
    if not repo_url:
        return None
    s = repo_url.strip()
    # حالت SSH مانند git@github.com:owner/repo(.git)
    m_ssh = re.match(r"git@github\.com:([^/]+)/([^/]+)(?:\.git)?$", s)
    if m_ssh:
        owner, repo = m_ssh.group(1), m_ssh.group(2)
        return f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"
    # حالت‌های http/https با/بدون www و با/بدون .git
    m_http = re.search(r"(?:https?://)?(?:www\.)?github\.com/([^/]+)/([^/]+)", s)
    if not m_http:
        return None
    owner, repo = m_http.group(1), m_http.group(2)
    repo = repo[:-4] if repo.endswith('.git') else repo
    return f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"


def update_code_from_repo(repo_url: str, branch: str, role: str, controller_url: str = None, headers=None):
    url = _github_zip_url(repo_url, branch)
    if not url:
        log(f"update: invalid repo url -> repo={repo_url!r} branch={branch!r}")
        return False
    tmpdir = tempfile.mkdtemp(prefix="dns_loki_node_")
    zip_path = os.path.join(tmpdir, "src.zip")
    try:
        # try direct from GitHub first
        try:
            log(f"update: downloading from GitHub codeload -> {url}")
            with urlopen(url, timeout=30) as resp, open(zip_path, "wb") as f:
                shutil.copyfileobj(resp, f)
        except Exception:
            # fallback via controller proxy endpoint if available
            if controller_url:
                try:
                    log(f"update: GitHub direct failed; trying controller proxy {controller_url}/v1/code/archive")
                    r = requests.get(
                        f"{controller_url}/v1/code/archive",
                        params={"repo": repo_url, "branch": branch},
                        timeout=45,
                        stream=True,
                        headers=headers,
                    )
                    r.raise_for_status()
                    with open(zip_path, "wb") as f:
                        for chunk in r.iter_content(chunk_size=65536):
                            if chunk:
                                f.write(chunk)
                except Exception:
                    log("update: controller proxy download failed")
                    return False
            else:
                log("update: GitHub download failed and no controller_url provided for fallback")
                return False
        log("update: download ok; extracting zip")
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(tmpdir)
        root = None
        # اولویت: دایرکتوری که agent/agent.py دارد
        for name in os.listdir(tmpdir):
            p = os.path.join(tmpdir, name)
            if os.path.isdir(p):
                if os.path.exists(os.path.join(p, "agent", "agent.py")):
                    root = p
                    break
                if root is None and name.startswith("dns-loki-"):
                    root = p
        if not root:
            # fallback: اولین دایرکتوری موجود
            for name in os.listdir(tmpdir):
                p = os.path.join(tmpdir, name)
                if os.path.isdir(p):
                    root = p
                    break
        if not root:
            log("update: could not detect source root after extraction")
            return False
        # Ensure destination directories exist
        Path(f"{WORK_DIR}/agent").mkdir(parents=True, exist_ok=True)
        Path(f"{WORK_DIR}/docker/dns").mkdir(parents=True, exist_ok=True)
        Path(f"{WORK_DIR}/docker/proxy").mkdir(parents=True, exist_ok=True)
        # Always update agent code
        shutil.copy2(os.path.join(root, "agent", "agent.py"), f"{WORK_DIR}/agent/agent.py")
        if os.path.exists(os.path.join(root, "agent", "requirements.txt")):
            shutil.copy2(os.path.join(root, "agent", "requirements.txt"), f"{WORK_DIR}/agent/requirements.txt")
        # Update role-specific runtime files
        if role == "dns":
            # docker/dns and nftables
            dns_src = os.path.join(root, "docker", "dns")
            if os.path.isdir(dns_src):
                shutil.copy2(os.path.join(dns_src, "docker-compose.yml"), f"{WORK_DIR}/docker/dns/docker-compose.yml")
                shutil.copy2(os.path.join(dns_src, "Corefile"), f"{WORK_DIR}/docker/dns/Corefile")
        if role == "proxy":
            prx_src = os.path.join(root, "docker", "proxy")
            if os.path.isdir(prx_src):
                shutil.copy2(os.path.join(prx_src, "docker-compose.yml"), f"{WORK_DIR}/docker/proxy/docker-compose.yml")
                tmpl = os.path.join(prx_src, "sniproxy.conf.tmpl")
                if os.path.exists(tmpl):
                    shutil.copy2(tmpl, f"{WORK_DIR}/docker/proxy/sniproxy.conf.tmpl")
        # Reinstall agent deps (best-effort)
        try:
            log("update: installing/upgrading agent requirements (best-effort)")
            run(f"{WORK_DIR}/agent/venv/bin/pip install -r {WORK_DIR}/agent/requirements.txt", check=False)
        except Exception:
            log("update: pip install step failed (ignored)")
        return True
    finally:
        log("update: cleanup temp directory")
        shutil.rmtree(tmpdir, ignore_errors=True)


def read_domains_list():
    path = Path(DOMAINS_DIR) / "domains.lst"
    if not path.exists():
        return []
    lines = [l.strip() for l in path.read_text(encoding='utf-8').splitlines()]
    domains = [l for l in lines if l and not l.startswith('#')]
    return domains


def fetch_domains_from_api(controller_url: str, headers=None):
    try:
        r = requests.get(f"{controller_url}/v1/domains", timeout=5, headers=headers)
        if r.status_code == 200:
            items = r.json()
            if isinstance(items, list):
                # normalize here as well
                out = []
                seen = set()
                for d in items:
                    d = str(d).strip().lower()
                    if d.startswith('*.'):
                        d = d[2:]
                    if d and d not in seen:
                        seen.add(d)
                        out.append(d)
                return out
    except Exception:
        pass
    return []


def build_regex_from_domains(domains):
    # Convert list like ["amd.com", "*.amd.com"] into a regex alternation
    cleaned = []
    for d in domains:
        d = d.lstrip("*.")
        d = re.escape(d)
        cleaned.append(f"(.*\\.)?{d}")
    if not cleaned:
        return "^$"  # match nothing
    return "^(" + "|".join(cleaned) + ")\\.$"


def render_coredns_targets(domains, healthy_ips):
    regex = build_regex_from_domains(domains)
    lines = ["template IN A {", f"  match {regex}"]
    ttl = 60
    for ip in healthy_ips:
        lines.append(f"  answer \"{{{{ .Name }}}} {ttl} IN A {ip}\"")
    lines.append("  fallthrough")
    lines.append("}")
    return "\n".join(lines) + "\n"

def _ensure_acl_symlink():
    """برای CoreDNS native مسیر import را تضمین می‌کند.
    برای سه فایل override (acl, targets, v6block) symlink می‌سازد تا Corefile بتواند import کند.
    بی‌خطر و idempotent است.
    """
    try:
        Path("/etc/coredns").mkdir(parents=True, exist_ok=True)
        for name in ("acl.override", "targets.override", "v6block.override"):
            src = Path(f"{DEF_CORE_DNS_DIR}/{name}")
            dst = Path(f"/etc/coredns/{name}")
            # Always replace destination with a symlink to src (ln -sf semantics)
            try:
                if dst.exists() or dst.is_symlink():
                    dst.unlink()
            except Exception:
                pass
            try:
                os.symlink(src, dst)
            except Exception as e2:
                log(f"override: ensure symlink failed for {name} -> {e2}")
    except Exception as e:
        log(f"override: ensure symlink setup failed -> {e}")


def render_v6block(domains):
    regex = build_regex_from_domains(domains)
    return f"""template IN AAAA {{
  match {regex}
  rcode NOERROR
}}
"""

def render_coredns_acl(dns_clients, enforce: bool):
    """تولید فایل acl.override برای CoreDNS.
    اگر enforce=False باشد، فایل خالی/آزاد تولید می‌کنیم تا محدودیتی اعمال نشود.
    اگر enforce=True و لیست خالی باشد، همه مسدود می‌شوند.
    """
    if not enforce:
        return "# acl disabled\n"
    ipv4s = only_ipv4(dns_clients)
    lines = ["acl {"]
    for ip in ipv4s:
        lines.append(f"  allow net {ip}/32")
    lines.append("  block")
    lines.append("}")
    return "\n".join(lines) + "\n"


def reload_coredns():
    # If running via Docker, send HUP to PID 1 in the container
    try:
        res = run(f"docker compose -f {DEF_CORE_DNS_DIR}/docker-compose.yml ps -q coredns", check=False)
        if res.returncode == 0 and res.stdout and res.stdout.strip():
            run(f"docker compose -f {DEF_CORE_DNS_DIR}/docker-compose.yml exec -T coredns kill -HUP 1", check=False)
            return
    except Exception:
        pass
    # Otherwise, try native services (fallback)
    run("systemctl restart coredns-native", check=False)
    run("systemctl restart coredns", check=False)


def render_sniproxy_conf(domains):
    table_lines = []
    for d in domains:
        d2 = d.lstrip("*.")
        table_lines.append(f"    {d2} *")
        table_lines.append(f"    .{d2} *")
    template_path = Path(DEF_PROXY_DIR) / "sniproxy.conf.tmpl"
    base = template_path.read_text()
    table_block = "\n".join(table_lines)
    return base.replace("#__TABLE__", table_block)


def restart_sniproxy():
    # If container exists, try graceful reload first; otherwise ensure it's up
    log("sniproxy: restart requested")
    # Ensure docker is available
    if not ensure_docker_running():
        log("sniproxy: docker not available; aborting restart for now")
        return
    # Check docker compose availability
    has_compose = (run("docker compose version", check=False).returncode == 0)
    if not has_compose:
        log("sniproxy: 'docker compose' not available; will use direct 'docker run' fallback")
    ps = run(f"docker compose -f {DEF_PROXY_DIR}/docker-compose.yml ps -q sniproxy", check=False)
    has_container = bool(ps.stdout and ps.stdout.strip())
    log(f"sniproxy: container present={has_container}")
    if has_container:
        log("sniproxy: attempting HUP reload")
        res = run(f"docker compose -f {DEF_PROXY_DIR}/docker-compose.yml kill --signal=HUP sniproxy", check=False)
        log(f"sniproxy: HUP rc={res.returncode}")
        if res.returncode == 0:
            log("sniproxy: reloaded via HUP")
            return
        # Fallback to restart if HUP unsupported or container not running
        log("sniproxy: HUP failed; attempting restart")
        if has_compose:
            res2 = run(f"docker compose -f {DEF_PROXY_DIR}/docker-compose.yml restart sniproxy", check=False)
            log(f"sniproxy: restart rc={res2.returncode}")
        else:
            # direct restart via docker if compose missing
            res2 = run("docker restart sniproxy", check=False)
            log(f"sniproxy: docker restart rc={res2.returncode}")
        return
    # No container yet -> bring it up
    log("sniproxy: container not found; bringing up with compose up -d")
    if has_compose:
        res3 = run(f"docker compose -f {DEF_PROXY_DIR}/docker-compose.yml up -d sniproxy", check=False)
        log(f"sniproxy: up -d rc={res3.returncode}")
        if res3.returncode == 0:
            return
        log("sniproxy: compose up failed; trying direct docker run")
    # Fallback: direct docker run (host network)
    run("docker rm -f sniproxy", check=False)
    cmd = (
        f"docker run -d --name sniproxy --restart unless-stopped --network host "
        f"-v {DEF_PROXY_DIR}/sniproxy.conf:/etc/sniproxy.conf "
        f"lancachenet/sniproxy:latest /usr/sbin/sniproxy -f -c /etc/sniproxy.conf"
    )
    res4 = run(cmd, check=False)
    log(f"sniproxy: docker run rc={res4.returncode}")


def _is_container_running(compose_file: str, service: str) -> bool:
    try:
        res = run(f"docker compose -f {compose_file} ps -q {service}", check=False)
        if res.returncode == 0 and res.stdout and res.stdout.strip():
            return True
    except Exception:
        pass
    # Fallback to plain docker in case compose is unavailable
    try:
        res2 = run(f"docker ps -q --filter name=^{service}$ --filter status=running", check=False)
        if res2.returncode == 0 and res2.stdout and res2.stdout.strip():
            return True
    except Exception:
        pass
    return False


def nft_ensure_set(set_name: str):
    # Ensure a named set exists; create if missing
    res = run(f"nft list set inet filter {set_name}", check=False)
    if res.returncode != 0:
        run(f"nft add set inet filter {set_name} {{ type ipv4_addr; flags interval; }}", check=False)

def only_ipv4(ips):
    out = []
    for s in (ips or []):
        try:
            ip = ipaddress.ip_address(str(s))
            if ip.version == 4:
                out.append(str(ip))
        except Exception:
            continue
    return out


def nft_replace_set(set_name: str, ips):
    if not ips:
        # clear set
        log(f"nft: clearing set {set_name} (no IPs provided)")
        res = run(f"nft flush set inet filter {set_name}", check=False)
        if res.returncode != 0:
            log(f"nft: failed to flush {set_name} -> rc={res.returncode}")
        return
    elements = ", ".join(ips)
    log(f"nft: updating set {set_name} with {len(ips)} IPs -> {elements}")
    res1 = run(f"nft flush set inet filter {set_name}", check=False)
    if res1.returncode != 0:
        log(f"nft: failed to flush {set_name} -> rc={res1.returncode}")
    res2 = run(f"nft add element inet filter {set_name} {{ {elements} }}", check=False)
    if res2.returncode != 0:
        log(f"nft: failed to add elements to {set_name} -> rc={res2.returncode}")
    else:
        log(f"nft: successfully updated {set_name} with {len(ips)} IPs")


def nft_list_set(set_name: str):
    try:
        res = run(f"nft list set inet filter {set_name}", check=False)
        if res.returncode != 0 or not getattr(res, "stdout", b""):
            return []
        # stdout is bytes due to PIPE; decode safely
        txt = res.stdout.decode(errors="ignore") if isinstance(res.stdout, (bytes, bytearray)) else str(res.stdout)
        m = re.search(r"elements\s*=\s*\{([^}]*)\}", txt, re.S)
        if not m:
            return []
        raw = m.group(1)
        elems = [e.strip() for e in raw.split(",") if e.strip()]
        return only_ipv4(elems)
    except Exception:
        return []


def apply_dns_policy(enforce: bool):
    rules_file = "/opt/dns-proxy/nftables/dns_enforced.nft" if enforce else "/opt/dns-proxy/nftables/dns.nft"
    run(f"nft -f {rules_file}", check=False)
    # Ensure set exists for future updates
    nft_ensure_set("allow_dns_clients")


def apply_proxy_policy(enforce: bool):
    rules_file = "/opt/dns-proxy/nftables/proxy_enforced.nft" if enforce else "/opt/dns-proxy/nftables/proxy.nft"
    run(f"nft -f {rules_file}", check=False)
    nft_ensure_set("allow_proxy_clients")


def tls_health_check(ip: str, sni_host: str, timeout=3.0) -> bool:
    import socket, ssl
    try:
        ctx = ssl.create_default_context()
        sock = socket.create_connection((ip, 443), timeout=timeout)
        ssock = ctx.wrap_socket(sock, server_hostname=sni_host)
        # send minimal HTTP request
        req = f"HEAD / HTTP/1.1\r\nHost: {sni_host}\r\nConnection: close\r\n\r\n"
        ssock.send(req.encode())
        data = ssock.recv(1)
        ssock.close()
        return True
    except Exception:
        return False


def tls_probe_latency(ip: str, sni_host: str, timeout=3.0):
    """انجام هندشیک TLS و ارسال یک درخواست HEAD کوچک برای سنجش تاخیر.
    خروجی: (ok: bool, latency_ms: float|None)
    """
    import socket, ssl
    t0 = time.perf_counter()
    try:
        ctx = ssl.create_default_context()
        sock = socket.create_connection((ip, 443), timeout=timeout)
        ssock = ctx.wrap_socket(sock, server_hostname=sni_host)
        req = f"HEAD / HTTP/1.1\r\nHost: {sni_host}\r\nConnection: close\r\n\r\n"
        ssock.send(req.encode())
        _ = ssock.recv(1)
        ssock.close()
        dt_ms = (time.perf_counter() - t0) * 1000.0
        return True, dt_ms
    except Exception:
        return False, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text())
    role = cfg.get("role")
    controller_url = cfg.get("controller_url")
    git_repo = cfg.get("git_repo")
    git_branch = cfg.get("git_branch", "main")
    # INTERNAL_TOKEN can be provided via env or config for authenticating to controller
    internal_token = (os.environ.get("INTERNAL_TOKEN") or str(cfg.get("internal_token") or "")).strip()
    headers = _auth_headers(internal_token)

    domains_version_seen = None
    # track applied agents_version on disk to avoid loops across restarts
    agents_version_applied = 0
    try:
        if Path(LAST_VER_FILE).exists():
            agents_version_applied = int(Path(LAST_VER_FILE).read_text().strip())
            log(f"init: last_agents_version found -> {agents_version_applied}")
        else:
            log("init: last_agents_version not found; default 0")
    except Exception as e:
        # keep default 0 when unreadable
        log(f"init: failed reading last_agents_version -> {e}")
    self_registered = False
    my_ip = None

    while True:
        try:
            conf = requests.get(f"{controller_url}/v1/config", timeout=5, headers=headers).json()
        except Exception as e:
            log(f"loop: failed fetching controller config -> {e}")
            time.sleep(5)
            continue

        # Self-discover ip once
        if not self_registered:
            try:
                my_ip = requests.get("https://api.ipify.org", timeout=5).text.strip()
                self_registered = True
            except Exception:
                my_ip = None

        # Build client allowlists per scope
        dns_clients = [str(c["ip"]) for c in conf.get("clients", []) if "dns" in c.get("scope", ["dns", "proxy"]) ]
        proxy_clients = [str(c["ip"]) for c in conf.get("clients", []) if "proxy" in c.get("scope", ["dns", "proxy"]) ]
        proxies = [n for n in conf.get("nodes", []) if n.get("role") == "proxy" and n.get("enabled", True)]
        proxy_ips = [str(n["ip"]) for n in proxies]
        # DNS nodes (Iran) are the only legitimate callers of proxy servers
        dns_node_ips = [str(n["ip"]) for n in conf.get("nodes", []) if n.get("role") == "dns" and n.get("enabled", True)]
        enforce_dns = conf.get("enforce_dns_clients", True)
        enforce_proxy = conf.get("enforce_proxy_clients", False)
        
        # Log configuration details for debugging
        log(f"config: role={role}, enforce_dns={enforce_dns}, enforce_proxy={enforce_proxy}")
        log(f"config: total_clients={len(conf.get('clients', []))}, dns_clients={len(dns_clients)}, proxy_clients={len(proxy_clients)}")
        log(f"config: total_nodes={len(conf.get('nodes', []))}, proxy_nodes={len(proxies)}, dns_nodes={len(dns_node_ips)}")
        if dns_clients:
            log(f"config: dns_clients_list -> {dns_clients}")
        if proxy_clients:
            log(f"config: proxy_clients_list -> {proxy_clients}")
        if dns_node_ips:
            log(f"config: dns_node_ips -> {dns_node_ips}")

        # Handle code update trigger for agents
        code_repo = conf.get("code_repo") or "https://github.com/lokidv/dns-loki.git"
        code_branch = conf.get("code_branch") or "main"
        agents_version_conf = int(conf.get("agents_version", 1))
        if agents_version_applied is None or agents_version_applied != agents_version_conf:
            log(f"update-check: target={agents_version_conf} applied={agents_version_applied} repo={code_repo} branch={code_branch}")
            try:
                update_success = update_code_from_repo(code_repo, code_branch, role or "", controller_url, headers=headers)
                log(f"update-check: update_code_from_repo returned {update_success}")
                if update_success:
                    try:
                        Path(LAST_VER_FILE).parent.mkdir(parents=True, exist_ok=True)
                        Path(LAST_VER_FILE).write_text(str(agents_version_conf))
                        log(f"update-apply: wrote last_agents_version={agents_version_conf}")
                    except Exception as e:
                        log(f"update-apply: failed writing last_agents_version -> {e}")
                    # Reflect applied version in-memory regardless of disk write to avoid stalls
                    agents_version_applied = agents_version_conf
                    log(f"update-apply: updated agents_version_applied to {agents_version_applied}")
                    
                    # Report success to controller
                    try:
                        report_data = {"ip": my_ip, "role": role, "agents_version_applied": agents_version_applied}
                        requests.post(f"{controller_url}/v1/nodes/register", json=report_data, timeout=5, headers=headers)
                        log(f"update-apply: reported success to controller")
                    except Exception as e:
                        log(f"update-apply: failed reporting to controller -> {e}")
                    
                    # restart self to load new code
                    try:
                        log("update-apply: restarting service dns-proxy-agent")
                        run("systemctl restart dns-proxy-agent", check=False)
                        time.sleep(2)
                    except Exception as e:
                        log(f"update-apply: restart failed -> {e}")
                else:
                    log("update-check: update_code_from_repo failed, will retry next cycle")
            except Exception as e:
                log(f"update-check: exception during update process -> {e}")
        else:
            # Versions match - still report to controller periodically
            if my_ip and agents_version_applied > 0:
                try:
                    report_data = {"ip": my_ip, "role": role, "agents_version_applied": agents_version_applied}
                    requests.post(f"{controller_url}/v1/nodes/register", json=report_data, timeout=5, headers=headers)
                except Exception:
                    pass  # Silent fail for periodic reports

        # Sync domains based on source of truth
        domains = []
        use_git = bool(conf.get("git_repo"))
        if use_git:
            if domains_version_seen != conf.get("domains_version"):
                ensure_git_repo(conf["git_repo"], conf.get("git_branch", "main"))
                domains_version_seen = conf.get("domains_version")
            domains = read_domains_list()
        else:
            # pull from API; refresh each loop is cheap, rendering is idempotent
            if domains_version_seen != conf.get("domains_version"):
                domains_version_seen = conf.get("domains_version")
            domains = fetch_domains_from_api(controller_url, headers=headers)
        # Fallback seed for testing if still empty
        if not domains:
            domains = ["amd.com", "*.amd.com"]

        healthy = []
        if role == "dns":
            log(f"dns: applying policy -> enforce={enforce_dns}")
            apply_dns_policy(enforce_dns)
            # Update nft set of allowed dns clients
            if enforce_dns:
                ipv4_clients = only_ipv4(dns_clients)
                log(f"dns: enforcement enabled, updating allowlist with {len(ipv4_clients)} clients -> {ipv4_clients}")
                nft_replace_set("allow_dns_clients", ipv4_clients)
            else:
                # When enforcement is disabled, clear the set to reflect runtime state
                log("dns: enforcement disabled, clearing allowlist")
                nft_replace_set("allow_dns_clients", [])
            # Health check proxies
            sni_host = domains[0].lstrip("*.")
            lat_map = {}
            best_ip, best_lat = None, None
            for ip in proxy_ips:
                ok, lat = tls_probe_latency(ip, sni_host, timeout=3.0)
                if ok:
                    healthy.append(ip)
                    lat_map[ip] = lat
                    if best_lat is None or lat < best_lat:
                        best_lat, best_ip = lat, ip
            # Fallback: اگر سالمی نبود، همه را استفاده کن
            selected = [best_ip] if healthy and best_ip else (proxy_ips if not healthy else [healthy[0]])
            # Render CoreDNS override files
            targets = render_coredns_targets(domains, selected)
            v6blk = render_v6block(domains)
            acltxt = render_coredns_acl(dns_clients, enforce_dns)
            Path(f"{DEF_CORE_DNS_DIR}/targets.override").write_text(targets)
            Path(f"{DEF_CORE_DNS_DIR}/v6block.override").write_text(v6blk)
            Path(f"{DEF_CORE_DNS_DIR}/acl.override").write_text(acltxt)
            # Ensure native CoreDNS can import ACL file (no-op for container)
            _ensure_acl_symlink()
            # Reload CoreDNS
            reload_coredns()

        if role == "proxy":
            log(f"proxy: applying policy -> enforce={enforce_proxy}")
            apply_proxy_policy(enforce_proxy)
            # Update nft set of allowed proxy clients
            if enforce_proxy:
                # Only allow Iran DNS nodes (required), plus any explicit proxy-scope clients (if defined)
                allowed_proxy_clients = sorted(set(proxy_clients + dns_node_ips))
                ipv4_allowed = only_ipv4(allowed_proxy_clients)
                log(f"proxy: enforcement enabled, updating allowlist with {len(ipv4_allowed)} clients -> {ipv4_allowed}")
                log(f"proxy: allowlist breakdown -> proxy_clients={proxy_clients}, dns_nodes={dns_node_ips}")
                nft_replace_set("allow_proxy_clients", ipv4_allowed)
            else:
                # When enforcement is disabled, clear the set to reflect runtime state
                log("proxy: enforcement disabled, clearing allowlist")
                nft_replace_set("allow_proxy_clients", [])
            # Render sniproxy.conf from template
            conf_txt = render_sniproxy_conf(domains)
            out_path = Path(DEF_PROXY_DIR) / "sniproxy.conf"
            old = out_path.read_text() if out_path.exists() else ""
            if conf_txt != old:
                out_path.write_text(conf_txt)
                # Ensure docker is up before attempting restart
                if ensure_docker_running():
                    restart_sniproxy()
                else:
                    log("sniproxy: postponed start; docker not ready")
            else:
                # Ensure sniproxy is up even if config didn't change (e.g., docker installed later)
                if not _is_container_running(f"{DEF_PROXY_DIR}/docker-compose.yml", "sniproxy"):
                    log("sniproxy: not running; attempting to start")
                    if ensure_docker_running():
                        restart_sniproxy()
                    else:
                        log("sniproxy: start skipped; docker not ready")

        # Build diagnostics after applying configs
        # Gather runtime nft set elements (best-effort)
        nft_dns_elems = nft_list_set("allow_dns_clients") if role == "dns" else None
        nft_proxy_elems = nft_list_set("allow_proxy_clients") if role == "proxy" else None
        # Compute effective allowlists from config perspective
        proxy_effective_allow = sorted(set(proxy_clients + dns_node_ips)) if proxy_clients or dns_node_ips else []
        diag = {
            "role": role,
            "domains_count": len(domains),
            "proxies_total": len(proxy_ips),
            "proxies_healthy": len(healthy) if healthy else 0,
            "selected_proxy": (best_ip if role == "dns" else None),
            "selected_latency_ms": (round(best_lat, 1) if (role == "dns" and best_lat is not None) else None),
            "proxies_latency_ms": (lat_map if role == "dns" else None),
            "enforce_dns": bool(enforce_dns),
            "enforce_proxy": bool(enforce_proxy),
            "client_allowlists": {
                "dns_clients_configured": only_ipv4(dns_clients),
                "proxy_clients_configured": only_ipv4(proxy_clients),
                "proxy_effective_allowlist": only_ipv4(proxy_effective_allow),
            },
            "nft_sets": {
                "allow_dns_clients": (nft_dns_elems or []),
                "allow_proxy_clients": (nft_proxy_elems or []),
            },
            "svc": {
                "coredns_running": _is_container_running(f"{DEF_CORE_DNS_DIR}/docker-compose.yml", "coredns") if role == "dns" else None,
                "sniproxy_running": _is_container_running(f"{DEF_PROXY_DIR}/docker-compose.yml", "sniproxy") if role == "proxy" else None,
            },
            "files": {
                "targets_override": {
                    "exists": Path(f"{DEF_CORE_DNS_DIR}/targets.override").exists(),
                    "size": (Path(f"{DEF_CORE_DNS_DIR}/targets.override").stat().st_size if Path(f"{DEF_CORE_DNS_DIR}/targets.override").exists() else 0),
                },
                "acl_override": {
                    "exists": Path(f"{DEF_CORE_DNS_DIR}/acl.override").exists(),
                    "size": (Path(f"{DEF_CORE_DNS_DIR}/acl.override").stat().st_size if Path(f"{DEF_CORE_DNS_DIR}/acl.override").exists() else 0),
                },
                "sniproxy_conf": {
                    "exists": Path(f"{DEF_PROXY_DIR}/sniproxy.conf").exists(),
                    "size": (Path(f"{DEF_PROXY_DIR}/sniproxy.conf").stat().st_size if Path(f"{DEF_PROXY_DIR}/sniproxy.conf").exists() else 0),
                },
            },
        }

        # Refresh applied version from disk each loop (handles manual creation or post-start updates)
        try:
            if Path(LAST_VER_FILE).exists():
                _cur = int(Path(LAST_VER_FILE).read_text().strip())
                if agents_version_applied != _cur:
                    log(f"loop: detected last_agents_version change on disk -> {_cur}")
                    agents_version_applied = _cur
        except Exception as e:
            log(f"loop: failed reading last_agents_version -> {e}")

        # Heartbeat / upsert node with diagnostics and version (always send)
        try:
            hb = {
                "role": role,
                "enabled": True,
                "agents_version_applied": int(agents_version_applied),
                "ts": time.time(),
                "diag": diag,
            }
            if my_ip:
                hb["ip"] = my_ip
            requests.post(f"{controller_url}/v1/nodes", json=hb, timeout=5)
        except Exception as e:
            log(f"heartbeat: failed to post -> {e}")

        time.sleep(cfg.get("health_check_interval_seconds", 10))


if __name__ == "__main__":
    main()
