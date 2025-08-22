# DNS-LOKI Delivery Plan (updated: 2025-08-09)

A concise, actionable plan showing current status, exactly what to do now, and the roadmap.

## برنامه فارسی — هدف: سناریو C (۲× DNS ایران + چند Proxy خارج)

این بخش به‌صورت خلاصه و عملیاتی، وضعیت فعلی، فهرست سرورها، کارهای فوری و نقشهٔ راه را توضیح می‌دهد.

### وضعیت فعلی
- اسکریپت نصب و اجزای سیستم آمادهٔ استقرار هستند (`scripts/install.sh`، `controller/api.py`، `agent/agent.py`).
- فعلاً فقط نود DNS ایران با IP `185.84.158.34` در حال پیشروی است. نود دوم ایران `87.248.154.86` هنوز نصب نشده.
- سه سرور آمریکا برای Proxy آماده‌اند ولی هنوز نصب نشده‌اند.
- Enforcement برای DNS به‌صورت پیش‌فرض روشن است و برای Proxy می‌تواند پس از تست فعال شود.

### فهرست سرورها (Inventory)
- Proxyهای آمریکا:
  - `144.172.98.5`
  - `144.172.103.229`
  - `144.172.103.230`
- DNSهای ایران:
  - فعال/درحال‌پیشروی: `185.84.158.34`
  - بعدی (برنامه نصب): `87.248.154.86`

### همین الان دقیقاً چه کار کنیم (۳۰–۶۰ دقیقه آینده)
1) نصب Proxy روی هر ۳ سرور آمریکا (روی هر سرور جداگانه اجرا شود؛ `<CONTROLLER_IP>` را با IP کنترلر جایگزین کنید)
```bash
apt-get update -y && apt-get install -y git
git clone https://github.com/lokidv/dns-loki.git && cd dns-loki
sudo ./scripts/install.sh \
  --role proxy \
  --controller-url http://<CONTROLLER_IP>:8080
```
سرورهای آمریکا که باید این دستور روی آن‌ها اجرا شود:
- 144.172.98.5
- 144.172.103.229
- 144.172.103.230

2) تایید ثبت Proxyها در Controller (روی کنترلر اجرا شود)
```bash
curl -sS http://<CONTROLLER_IP>:8080/v1/nodes | jq .
# در صورت نبودن هر IP در خروجی، دستی اضافه کنید (برای هر Proxy یکبار):
curl -sS -X POST http://<CONTROLLER_IP>:8080/v1/nodes \
  -H 'Content-Type: application/json' \
  -H 'X-Internal-Token: <INTERNAL_TOKEN>' \
  -d '{"ip":"144.172.98.5","role":"proxy","enabled":true}' | jq .
curl -sS -X POST http://<CONTROLLER_IP>:8080/v1/nodes \
  -H 'Content-Type: application/json' \
  -H 'X-Internal-Token: <INTERNAL_TOKEN>' \
  -d '{"ip":"144.172.103.229","role":"proxy","enabled":true}' | jq .
curl -sS -X POST http://<CONTROLLER_IP>:8080/v1/nodes \
  -H 'Content-Type: application/json' \
  -H 'X-Internal-Token: <INTERNAL_TOKEN>' \
  -d '{"ip":"144.172.103.230","role":"proxy","enabled":true}' | jq .
```

3) نصب DNS روی ایران (سرور فعال فعلی)
```bash
apt-get update -y && apt-get install -y git
git clone https://github.com/lokidv/dns-loki.git && cd dns-loki
sudo ./scripts/install.sh \
  --role dns \
  --controller-url http://<CONTROLLER_IP>:8080
```

4) همگام‌سازی دامنه‌ها و بررسی فایل‌های override روی نود DNS
```bash
curl -sS -X POST http://<CONTROLLER_IP>:8080/v1/domains/sync \
  -H 'X-Internal-Token: <INTERNAL_TOKEN>' | jq .
sed -n '1,200p' /opt/dns-proxy/docker/dns/targets.override
sed -n '1,200p' /opt/dns-proxy/docker/dns/v6block.override
```

5) تست‌های عملکردی (با فرض DNS ایران: 185.84.158.34)
```bash
DIG_DNS=185.84.158.34
dig @${DIG_DNS} A amd.com +short      # باید IPهای Proxy برگردد
dig @${DIG_DNS} AAAA amd.com +short   # باید خالی/NOERROR باشد (IPv6 مسدود)

# بررسی دسترسی به پورت‌های sniproxy روی هر Proxy
nc -zv 144.172.98.5 80;  nc -zv 144.172.98.5 443
nc -zv 144.172.103.229 80; nc -zv 144.172.103.229 443
nc -zv 144.172.103.230 80; nc -zv 144.172.103.230 443
```

6) تست کلاینت واقعی
- DNS کلاینت را فقط روی `185.84.158.34` بگذارید (Secondary حذف شود).
- یک دامنهٔ موجود در `domains.lst` (مثل amd.com یا docker.io) را باز کنید؛ ترافیک باید از SNI Proxy خارج عبور کند.

### پس از تایید: محدودسازی دسترسی (Enforcement)
1) افزودن IP مشتریان مجاز
```bash
curl -sS -X POST http://<CONTROLLER_IP>:8080/v1/clients -H 'Content-Type: application/json' \
  -d '{"ip":"<CLIENT_IP>","note":"customer1","scope":["dns","proxy"]}' | jq .
```
2) روشن کردن فلگ‌های محدودسازی
```bash
curl -sS -X POST http://<CONTROLLER_IP>:8080/v1/flags -H 'Content-Type: application/json' \
  -H 'X-Internal-Token: <INTERNAL_TOKEN>' \
  -d '{"enforce_dns_clients": true}' | jq .
curl -sS -X POST http://<CONTROLLER_IP>:8080/v1/flags -H 'Content-Type: application/json' \
  -H 'X-Internal-Token: <INTERNAL_TOKEN>' \
  -d '{"enforce_proxy_clients": true}' | jq .
```

### گام‌های آینده (Roadmap کوتاه)
- نصب نود DNS دوم در ایران روی `87.248.154.86` و قرار دادن هر دو DNS در دسترس مشتری.
- اتصال کامل Site ↔ Controller با توکن داخلی (مدیریت دامنه‌ها، کاربران، پلن‌ها).
- بهبود داشبورد وضعیت و مانیتورینگ سرویس‌ها.

---

## 1) Where we are now (Status)

- [x] Universal installer `scripts/install.sh` supports roles: `controller`, `dns`, `proxy`.
- [x] CoreDNS via Docker with multi-registry pull and native fallback (binary or apt) on block.
- [x] Agent `agent/agent.py` runs on nodes, syncs domains, manages nftables allow-lists.
- [x] Controller API `controller/api.py` with endpoints to sync domains, manage clients, flags, and nodes.
- [x] Base nftables rules for DNS/Proxy: `nftables/dns.nft`, `nftables/proxy.nft`.
- [x] Domain list repo prepared: https://github.com/lokidv/dmlist (file: `domains.lst`).
- [ ] At least one Proxy node deployed outside Iran and registered in Controller.
- [ ] At least one DNS node deployed in Iran and answering with Proxy IPs for target domains.
- [ ] Enforcement disabled by default (open) for testing; to be enabled after verification.

Notes:
- Scenario B (DNS in Iran + SNI Proxy outside) is the running baseline. Scenario C (2× DNS Iran + N× Proxy outside) is a near-term extension.

---

## 2) Do this now (next 30–60 minutes)

1) Deploy a Proxy node (outside Iran)
```bash
# On the proxy server (Ubuntu/Debian), as root or with sudo
apt-get update -y && apt-get install -y git
git clone https://github.com/lokidv/dns-loki.git && cd dns-loki
sudo ./scripts/install.sh \
  --role proxy \
  --controller-url http://<CONTROLLER_IP>:8080 \
  
```
- Expect: sniproxy container up, UDP/443 blocked by nftables, agent started.

2) Verify the Proxy node is registered in Controller
```bash
curl -sS http://<CONTROLLER_IP>:8080/v1/nodes | jq .
# If missing, add manually:
curl -sS -X POST http://<CONTROLLER_IP>:8080/v1/nodes \
  -H 'Content-Type: application/json' \
  -H 'X-Internal-Token: <INTERNAL_TOKEN>' \
  -d '{"ip":"<PROXY_PUBLIC_IP>","role":"proxy","enabled":true}' | jq .
```

3) Deploy a DNS node (inside Iran)
```bash
apt-get update -y && apt-get install -y git
git clone https://github.com/lokidv/dns-loki.git && cd dns-loki
sudo ./scripts/install.sh \
  --role dns \
  --controller-url http://<CONTROLLER_IP>:8080 \
  
```
- Expect: CoreDNS via Docker (or native fallback) up, agent started, base nft rules applied.

4) Trigger domain sync and verify overrides on DNS node
```bash
curl -sS -X POST http://<CONTROLLER_IP>:8080/v1/domains/sync \
  -H 'X-Internal-Token: <INTERNAL_TOKEN>' | jq .
# On the DNS node, verify the generated targets (should point A records to proxy IPs):
sed -n '1,200p' /opt/dns-proxy/docker/dns/targets.override
sed -n '1,200p' /opt/dns-proxy/docker/dns/v6block.override
```

5) Functional tests
```bash
# From the DNS node or a test host, check answers for a domain in domains.lst
DIG_DNS=<DNS_NODE_IP>
dig @${DIG_DNS} A amd.com +short
# Expect A = <PROXY_PUBLIC_IP>(s)
dig @${DIG_DNS} AAAA amd.com +short
# Expect empty/NOERROR (IPv6 blocked)

# Check sniproxy ports reachable
nc -zv <PROXY_PUBLIC_IP> 80
nc -zv <PROXY_PUBLIC_IP> 443
```

6) Test with a real client
- Set client DNS to only `<DNS_NODE_IP>` (remove Secondary DNS).
- Browse a domain from `domains.lst` (e.g., amd.com, docker.io). Traffic should go via the SNI Proxy.

If all OK, proceed to enforcement (Section 4).

---

## 3) One-time Controller install (if not already installed)
```bash
# On the controller server (can be the DNS node or separate)
apt-get update -y && apt-get install -y git
git clone https://github.com/lokidv/dns-loki.git && cd dns-loki
sudo ./scripts/install.sh \
  --role controller \
  --bind 0.0.0.0:8080 \
  

# Optional hardening later: set HOST=127.0.0.1 in /opt/dns-proxy/controller/.env and restart service
```

---

## 4) Enable enforcement (after tests pass)

1) Add/Manage allowed client IPs via Controller
```bash
# Allow only DNS
curl -sS -X POST http://<CONTROLLER_IP>:8080/v1/clients \
  -H 'Content-Type: application/json' \
  -H 'X-Internal-Token: <INTERNAL_TOKEN>' \
  -d '{"ip":"<CLIENT_IP>","note":"customer1","scope":["dns"]}' | jq .

# Allow only Proxy
curl -sS -X POST http://<CONTROLLER_IP>:8080/v1/clients \
  -H 'Content-Type: application/json' \
  -H 'X-Internal-Token: <INTERNAL_TOKEN>' \
  -d '{"ip":"<CLIENT_IP>","note":"customer1","scope":["proxy"]}' | jq .

# Allow both DNS+Proxy
curl -sS -X POST http://<CONTROLLER_IP>:8080/v1/clients \
  -H 'Content-Type: application/json' \
  -H 'X-Internal-Token: <INTERNAL_TOKEN>' \
  -d '{"ip":"<CLIENT_IP>","note":"customer1","scope":["dns","proxy"]}' | jq .
```

2) Turn on enforcement flags
```bash
# Enforce DNS first, verify, then Proxy
curl -sS -X POST http://<CONTROLLER_IP>:8080/v1/flags \
  -H 'Content-Type: application/json' \
  -d '{"enforce_dns_clients": true}' | jq .

curl -sS -X POST http://<CONTROLLER_IP>:8080/v1/flags \
  -H 'Content-Type: application/json' \
  -d '{"enforce_proxy_clients": true}' | jq .
```

Agent on nodes will update nftables sets `allow_dns_clients` and `allow_proxy_clients` automatically.

---

## 5) Automation and integration (Site ↔ Controller)

- منبع واحد حقیقت برای دامنه‌ها پایگاه‌داده Controller است که از طریق سرویس Site (Laravel + MySQL) مدیریت می‌شود.
- ارتباط داخلی Site با Controller باید با هدر `X-Internal-Token` انجام شود.
- دیگر از GitHub/dmlist یا Webhook برای همگام‌سازی استفاده نمی‌کنیم.

---

## 6) Architecture (short)

- Controller API (`controller/api.py`) مدیریت Sync دامنه‌ها، مشتریان، فلگ‌ها و رجیستری نودها را برعهده دارد.
- DNS در ایران: CoreDNS رکوردهای A دامنه‌های تعریف‌شده را به IPهای Proxy بازنویسی می‌کند؛ AAAA مسدود است.
- Proxy خارج از ایران: sniproxy بر اساس SNI/Host فوروارد می‌کند؛ UDP/443 مسدود برای ترجیح HTTP/2.
- Agent روی هر نود لیست IPهای مجاز را با nftables اعمال کرده و سرویس‌ها/کانفیگ را Sync می‌کند.
- منبع واحد حقیقت برای دامنه‌ها دیتابیس Controller است؛ مدیریت از طریق Site (Laravel + MySQL) انجام می‌شود.

---

## 7) Repo map (for quick reference)

- `scripts/install.sh` — universal installer for all roles; handles Docker, CoreDNS fallback, systemd services.
- `controller/api.py` — FastAPI app (served by uvicorn) for control-plane endpoints.
- `agent/agent.py` — agent daemon handling sync, nftables, and service restarts.
- `docker/dns/docker-compose.yml` — CoreDNS stack.
- `nftables/dns.nft` — base DNS firewall rules.
- `nftables/proxy.nft` — base Proxy firewall rules (incl. blocking UDP/443).
- External: `https://github.com/lokidv/dmlist` — domain list (`domains.lst`).

---

## 8) Acceptance criteria

- DNS answers A for domains in `domains.lst` with only Proxy IP(s); AAAA suppressed.
- HTTP/HTTPS traffic for those domains successfully passes via sniproxy outside Iran.
- Only allowed client IPs (as configured) can use DNS and Proxy when enforcement = true.
- تغییرات دامنه در Site/Controller باعث به‌روزرسانی نودها (از طریق `/v1/domains/sync`) می‌شود.
- System remains operable even if Docker registries are blocked (native CoreDNS fallback).

---

## 9) Risks & mitigations

- Registry blocks: mitigated by CoreDNS native fallback in installer.
- Client bypass via Secondary DNS: instruct clients to use only the provided DNS IP; optional network-level enforcement.
- HTTP/3 quirks: UDP/443 blocked on Proxy to prefer HTTP/2.
- Controller exposure: bind to 127.0.0.1 or firewall restrict 8080; استفاده از INTERNAL_TOKEN برای عملیات حساس.

---

## 10) Near-term roadmap (1–3 days)

- [ ] Deploy at least 2 Proxy nodes (HA) and 2 DNS nodes (Iran) — Scenario C ready.
- [ ] سخت‌سازی بیشتر احراز هویت داخلی Controller و رصد لاگ‌ها.
- [ ] Add healthcheck UI or status page for nodes/domains.
- [ ] CI hook to validate `domains.lst` format before merge.

---

## 11) Quick checklist (for you)

- [ ] Proxy node deployed and visible in `/v1/nodes`.
- [ ] DNS node deployed and serving A answers pointing to Proxy IP(s).
- [ ] Client tested successfully through the system.
- [ ] Enforcement enabled for your customer IP(s).
- [ ] INTERNAL_TOKEN روی Controller تنظیم شده و درخواست‌های حساس با آن ارسال می‌شوند.
