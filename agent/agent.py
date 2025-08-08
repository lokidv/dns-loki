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

DEF_CORE_DNS_DIR = "/opt/dns-proxy/docker/dns"
DEF_PROXY_DIR = "/opt/dns-proxy/docker/proxy"
WORK_DIR = "/opt/dns-proxy"
DOMAINS_DIR = f"{WORK_DIR}/domains"


def run(cmd, check=True):
    # print("RUN:", cmd)
    return subprocess.run(cmd, shell=True, check=check, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def ensure_git_repo(repo_url: str, branch: str):
    Path(DOMAINS_DIR).mkdir(parents=True, exist_ok=True)
    if not (Path(DOMAINS_DIR) / ".git").exists():
        run(f"git clone -b {branch} {repo_url} {DOMAINS_DIR}")
    else:
        run(f"git -C {DOMAINS_DIR} fetch --all")
        run(f"git -C {DOMAINS_DIR} reset --hard origin/{branch}")


def read_domains_list():
    path = Path(DOMAINS_DIR) / "domains.lst"
    if not path.exists():
        return []
    lines = [l.strip() for l in path.read_text(encoding='utf-8').splitlines()]
    domains = [l for l in lines if l and not l.startswith('#')]
    return domains


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
    run(f"docker compose -f {DEF_PROXY_DIR}/docker-compose.yml restart sniproxy", check=False)


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
    self_registered = False

    while True:
        try:
            conf = requests.get(f"{controller_url}/v1/config", timeout=5).json()
        except Exception:
            time.sleep(5)
            continue

        # Self-register node once
        if not self_registered:
            try:
                my_ip = requests.get("https://api.ipify.org", timeout=5).text.strip()
                requests.post(f"{controller_url}/v1/nodes", json={"ip": my_ip, "role": role, "enabled": True}, timeout=5)
                self_registered = True
            except Exception:
                pass

        clients = [c["ip"] for c in conf.get("clients", []) if "dns" in c.get("scope", ["dns","proxy"]) ]
        proxies = [n for n in conf.get("nodes", []) if n.get("role") == "proxy" and n.get("enabled", True)]
        proxy_ips = [str(n["ip"]) for n in proxies]
        enforce_dns = conf.get("enforce_dns_clients", False)
        enforce_proxy = conf.get("enforce_proxy_clients", False)

        # Sync domains if version bumped
        if conf.get("git_repo") and (domains_version_seen != conf.get("domains_version")):
            ensure_git_repo(conf["git_repo"], conf.get("git_branch", "main"))
            domains_version_seen = conf.get("domains_version")

        domains = read_domains_list()
        # If domains empty, ensure amd.com as seed to allow testing
        if not domains:
            domains = ["amd.com", "*.amd.com"]

        if role == "dns":
            apply_dns_policy(enforce_dns)
            # Update nft set of allowed dns clients
            if enforce_dns:
                nft_replace_set("allow_dns_clients", clients)
            # Health check proxies
            sni_host = domains[0].lstrip("*.")
            healthy = []
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

        time.sleep(cfg.get("health_check_interval_seconds", 10))


if __name__ == "__main__":
    main()
