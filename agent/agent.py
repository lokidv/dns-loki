import argparse
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


def run(cmd, check=True):
    # print("RUN:", cmd)
    return subprocess.run(cmd, shell=True, check=check, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


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
    m = re.search(r"github\\.com/([^/]+)/([^/.]+)", repo_url)
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    return f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"


def update_code_from_repo(repo_url: str, branch: str, role: str):
    url = _github_zip_url(repo_url, branch)
    if not url:
        return False
    tmpdir = tempfile.mkdtemp(prefix="dns_loki_node_")
    zip_path = os.path.join(tmpdir, "src.zip")
    try:
        with urlopen(url, timeout=30) as resp, open(zip_path, "wb") as f:
            shutil.copyfileobj(resp, f)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(tmpdir)
        root = None
        for name in os.listdir(tmpdir):
            p = os.path.join(tmpdir, name)
            if os.path.isdir(p) and name.startswith("dns-loki-"):
                root = p
                break
        if not root:
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
            run(f"{WORK_DIR}/agent/venv/bin/pip install -r {WORK_DIR}/agent/requirements.txt", check=False)
        except Exception:
            pass
        return True
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def read_domains_list():
    path = Path(DOMAINS_DIR) / "domains.lst"
    if not path.exists():
        return []
    lines = [l.strip() for l in path.read_text(encoding='utf-8').splitlines()]
    domains = [l for l in lines if l and not l.startswith('#')]
    return domains

def fetch_domains_from_api(controller_url: str):
    try:
        r = requests.get(f"{controller_url}/v1/domains", timeout=5)
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


def render_v6block(domains):
    regex = build_regex_from_domains(domains)
    return f"""template IN AAAA {{
  match {regex}
  rcode NOERROR
}}
"""


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
    # Prefer graceful reload to minimize downtime
    res = run(f"docker compose -f {DEF_PROXY_DIR}/docker-compose.yml kill --signal=HUP sniproxy", check=False)
    if res.returncode != 0:
        # Fallback to restart if HUP unsupported or container not running
        run(f"docker compose -f {DEF_PROXY_DIR}/docker-compose.yml restart sniproxy", check=False)


def _is_container_running(compose_file: str, service: str) -> bool:
    try:
        res = run(f"docker compose -f {compose_file} ps -q {service}", check=False)
        if res.returncode == 0 and res.stdout and res.stdout.strip():
            return True
    except Exception:
        pass
    return False


def nft_ensure_set(set_name: str):
    # Ensure a named set exists; create if missing
    res = run(f"nft list set inet filter {set_name}", check=False)
    if res.returncode != 0:
        run(f"nft add set inet filter {set_name} {{ type ipv4_addr; flags interval; }}", check=False)


def nft_replace_set(set_name: str, ips):
    if not ips:
        # clear set
        run(f"nft flush set inet filter {set_name}", check=False)
        return
    elements = ", ".join(ips)
    run(f"nft flush set inet filter {set_name}", check=False)
    run(f"nft add element inet filter {set_name} {{ {elements} }}", check=False)


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text())
    role = cfg.get("role")
    controller_url = cfg.get("controller_url")
    git_repo = cfg.get("git_repo")
    git_branch = cfg.get("git_branch", "main")

    domains_version_seen = None
    # track applied agents_version on disk to avoid loops across restarts
    agents_version_applied = None
    try:
        if Path(LAST_VER_FILE).exists():
            agents_version_applied = int(Path(LAST_VER_FILE).read_text().strip())
    except Exception:
        agents_version_applied = None
    self_registered = False
    my_ip = None

    while True:
        try:
            conf = requests.get(f"{controller_url}/v1/config", timeout=5).json()
        except Exception:
            time.sleep(5)
            continue

        # Self-discover ip once
        if not self_registered:
            try:
                my_ip = requests.get("https://api.ipify.org", timeout=5).text.strip()
                self_registered = True
            except Exception:
                my_ip = None

        clients = [c["ip"] for c in conf.get("clients", []) if "dns" in c.get("scope", ["dns","proxy"]) ]
        proxies = [n for n in conf.get("nodes", []) if n.get("role") == "proxy" and n.get("enabled", True)]
        proxy_ips = [str(n["ip"]) for n in proxies]
        enforce_dns = conf.get("enforce_dns_clients", False)
        enforce_proxy = conf.get("enforce_proxy_clients", False)

        # Handle code update trigger for agents
        code_repo = conf.get("code_repo") or "https://github.com/lokidv/dns-loki.git"
        code_branch = conf.get("code_branch") or "main"
        agents_version_conf = int(conf.get("agents_version", 1))
        if agents_version_applied is None or agents_version_applied != agents_version_conf:
            if update_code_from_repo(code_repo, code_branch, role or ""):
                try:
                    Path(LAST_VER_FILE).parent.mkdir(parents=True, exist_ok=True)
                    Path(LAST_VER_FILE).write_text(str(agents_version_conf))
                    # Reflect applied version in-memory to avoid repeated updates and report in heartbeat
                    agents_version_applied = agents_version_conf
                except Exception:
                    pass
                # restart self to load new code
                try:
                    run("systemctl restart dns-proxy-agent", check=False)
                    time.sleep(2)
                except Exception:
                    pass

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
            domains = fetch_domains_from_api(controller_url)
        # Fallback seed for testing if still empty
        if not domains:
            domains = ["amd.com", "*.amd.com"]

        healthy = []
        if role == "dns":
            apply_dns_policy(enforce_dns)
            # Update nft set of allowed dns clients
            if enforce_dns:
                nft_replace_set("allow_dns_clients", clients)
            # Health check proxies
            sni_host = domains[0].lstrip("*.")
            for ip in proxy_ips:
                if tls_health_check(ip, sni_host):
                    healthy.append(ip)
            # Fallback: if none healthy, use all to avoid total outage
            if not healthy:
                healthy = proxy_ips
            # Render CoreDNS override files
            targets = render_coredns_targets(domains, healthy)
            v6blk = render_v6block(domains)
            Path(f"{DEF_CORE_DNS_DIR}/targets.override").write_text(targets)
            Path(f"{DEF_CORE_DNS_DIR}/v6block.override").write_text(v6blk)
            # Reload CoreDNS
            reload_coredns()

        if role == "proxy":
            apply_proxy_policy(enforce_proxy)
            # Update nft set of allowed proxy clients
            if enforce_proxy:
                nft_replace_set("allow_proxy_clients", clients)
            # Render sniproxy.conf from template
            conf_txt = render_sniproxy_conf(domains)
            out_path = Path(DEF_PROXY_DIR) / "sniproxy.conf"
            old = out_path.read_text() if out_path.exists() else ""
            if conf_txt != old:
                out_path.write_text(conf_txt)
                restart_sniproxy()

        # Build diagnostics after applying configs
        diag = {
            "role": role,
            "domains_count": len(domains),
            "proxies_total": len(proxy_ips),
            "proxies_healthy": len(healthy) if healthy else 0,
            "enforce_dns": bool(enforce_dns),
            "enforce_proxy": bool(enforce_proxy),
            "svc": {
                "coredns_running": _is_container_running(f"{DEF_CORE_DNS_DIR}/docker-compose.yml", "coredns") if role == "dns" else None,
                "sniproxy_running": _is_container_running(f"{DEF_PROXY_DIR}/docker-compose.yml", "sniproxy") if role == "proxy" else None,
            },
            "files": {
                "targets_override": {
                    "exists": Path(f"{DEF_CORE_DNS_DIR}/targets.override").exists(),
                    "size": (Path(f"{DEF_CORE_DNS_DIR}/targets.override").stat().st_size if Path(f"{DEF_CORE_DNS_DIR}/targets.override").exists() else 0),
                },
                "sniproxy_conf": {
                    "exists": Path(f"{DEF_PROXY_DIR}/sniproxy.conf").exists(),
                    "size": (Path(f"{DEF_PROXY_DIR}/sniproxy.conf").stat().st_size if Path(f"{DEF_PROXY_DIR}/sniproxy.conf").exists() else 0),
                },
            },
        }

        # Heartbeat / upsert node with diagnostics and version (always send)
        try:
            hb = {
                "role": role,
                "enabled": True,
                "agents_version_applied": int(agents_version_applied) if agents_version_applied is not None else None,
                "ts": time.time(),
                "diag": diag,
            }
            if my_ip:
                hb["ip"] = my_ip
            requests.post(f"{controller_url}/v1/nodes", json=hb, timeout=5)
        except Exception:
            pass

        time.sleep(cfg.get("health_check_interval_seconds", 10))


if __name__ == "__main__":
    main()
