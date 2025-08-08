# PROJECT_PROMPT: DNS + SNI Proxy (Scenario C, IP-only)

## هدف (چی می‌خواهیم و چه مشکلی را حل می‌کند)
- چی می‌خواهیم:
  - راه‌اندازی سرویس DNS + SNI Proxy فروش‌محور برای عبور از محدودیت‌های مبتنی بر IP ایران با تجربهٔ کاربری پایدار و سریع.
  - سناریو C: دو DNS داخل ایران + چند SNI Proxy خارج با Health-check و Failover.
  - فقط IP به کاربر داده می‌شود (بدون دامنه)، بنابراین DoH/DoT سمت کاربر ارائه نمی‌شود.
  - مدیریت دامنه‌ها از Git به‌عنوان SSoT؛ با یک فراخوانی API همه نودها Sync و Reload/Restart شوند.
  - مدیریت پویا IP مشتریان مجاز از طریق API (افزودن/حذف فوری بدون ری‌استارت سرویس‌ها).
- چه مشکلی حل می‌کند:
  - دور زدن فیلترینگ و محدودیت‌های مبتنی بر IP ایران برای دامنه‌های مشخص، بدون نیاز به VPN عمومی.
  - ارائهٔ دسترسی پایدار با توزیع بار و Failover خودکار میان چند SNI Proxy خارج.
  - کنترل دقیق فروش: باز بودن سرویس فقط برای IP مشتریان خریدکرده؛ امکان مدیریت سریع فهرست مشتریان.
  - جلوگیری از پروکسی باز (Open Proxy) با allowlist دامنه‌ها و ACL مبتنی بر IP.

---

## معماری
- دو VPS داخل ایران: CoreDNS روی پورت‌های 53/UDP و 53/TCP.
- دو یا سه VPS خارج: SniDust در Docker روی 80/443/TCP (443/UDP مسدود).
- Control-Plane مرکزی (API) + Agent سبک روی هر نود (ایران و خارج).
- SSoT دامنه‌ها در Git (`domains.lst`)؛ Pull توسط Agent‌ها.
- Health-check روی هر DNS ایران: هر 5–10 ثانیه سلامت IPهای SniDust را بررسی و پاسخ‌های DNS را بر اساس IPهای سالم تولید می‌کند. TTL رکوردها 30–60s.

## سیاست‌ها و محدودیت‌ها
- فقط IPv4: برای دامنه‌های هدف رکورد AAAA برگردانده نشود (NOERROR/empty).
- DoH/DoT سمت کاربر ارائه نمی‌شود (TLS بدون دامنه مشکل اعتبار دارد). تمرکز بر DNS روی 53/UDP,TCP.
- روی سرورهای خارج UDP/443 بسته تا HTTP/3 غیرفعال و HTTP/2 اجباری شود.
- دسترسی DNS و Proxy فقط برای IPهای مجاز (allowlist) باز است.

## رفتار مورد انتظار
- DNS ایران:
  - دامنه‌های موجود در `domains.lst`: فقط A-record به سمت IPهای «سالم» SniDust برگردان.
  - برای AAAA همان دامنه‌ها: پاسخ NOERROR بدون رکورد.
  - سایر دامنه‌ها: فوروارد به Resolver مطمئن (مثلاً 1.1.1.1 و 1.0.0.1).
  - دسترسی به 53 فقط برای IPهای مجاز.
- SniDust خارج:
  - فقط دامنه‌های allowlist از `domains.lst` سرویس‌دهی شوند.
  - دسترسی به 80/443 فقط برای IPهای مجاز.
  - 443/UDP مسدود؛ نرخ‌دهی پایه فعال.
- Control-Plane/Agent:
  - API برای مدیریت IPهای مجاز و تریگر Sync دامنه‌ها.
  - Agent: Pull از Git، تولید فایل‌های کانفیگ، Reload/Restart سرویس‌ها بدون Downtime.
  - فایروال با nftables sets/ipset برای تغییرات سریع و اتمی.

## API (کنترل‌پلین)
- کلاینت‌ها (IP مجاز):
  - POST `/v1/clients`  
    Body:
    ```json
    { "ip": "203.0.113.25", "note": "user123", "scope": ["dns", "proxy"] }
    ```
  - DELETE `/v1/clients/{ip}`
  - GET `/v1/clients`
- دامنه‌ها (SSoT Sync):
  - POST `/v1/domains/sync` → Agentها روی نودها Pull از Git → generate → apply (DNS reload + SniDust restart در صورت تغییر)
- سلامت:
  - GET `/v1/health` → وضعیت نودها + لیست IPهای سالم SniDust + زمان آخرین Sync

## پیکربندی‌ها و نمونه فایل‌ها
- CoreDNS (ایران) – نمونه مینیمال:
```txt
. {
  log
  errors
  cache 30
  reload

  # دامنه‌های هدف: پاسخ A از فایل رندرشده توسط Agent
  import /etc/coredns/targets.override

  # AAAA نده برای دامنه‌های هدف
  template IN AAAA {
    match ^(.*\.)?(reddit\.com|redd\.it|redditmedia\.com|redditstatic\.com)\.$
    rcode NOERROR
  }

  # سایر دامنه‌ها
  forward . 1.1.1.1 1.0.0.1
}
```
- `/etc/coredns/targets.override` (خروجی Agent بر اساس IPهای سالم SniDust):
```txt
template IN A {
  match ^(.*\.)?(reddit\.com|redd\.it|redditmedia\.com|redditstatic\.com)\.$
  answer "{{ .Name }} 60 IN A 203.0.113.10"
  answer "{{ .Name }} 60 IN A 203.0.113.11"
  fallthrough
}
```
- SniDust (خارج):
  - Docker Compose با mount فایل `99-custom.lst` (تولید شده از `domains.lst`).
  - روی تغییر `99-custom.lst` فقط سرویس SniDust `restart` شود.
  - فایروال: 80/443 برای `@allow_proxy_clients` و مسدودسازی 443/UDP.

## فایروال (nftables sets)
- ایران (DNS): اجازه به 53/udp,53/tcp فقط از `@allow_dns_clients`.
- خارج (Proxy): اجازه به 80/tcp, 443/tcp فقط از `@allow_proxy_clients`.
- Agent روی تغییرات API، عضو setها را اضافه/حذف می‌کند (بدون ری‌استارت سرویس‌ها).

## Health-check و Failover
- هر 5–10 ثانیه برای هر IP SniDust:
  - TCP 443 → TLS با SNI یکی از دامنه‌های `domains.lst`.
  - پاسخ‌های 200/301/302/403 قابل قبول.
  - لیست IPهای سالم به‌روزرسانی و CoreDNS graceful reload شود.
  - خرابی یک IP ظرف ≤10–30 ثانیه از پاسخ‌های DNS حذف شود.

## تست و معیار پذیرش (Acceptance)
- افزودن IP مشتری با `POST /v1/clients` → همان لحظه DNS و Proxy برای آن IP باز شود.
- حذف IP مشتری → بلاک شدن فوری در DNS و Proxy.
- تغییر `domains.lst` و فراخوانی `POST /v1/domains/sync` → به‌روزرسانی پاسخ‌های DNS و allowlist SniDust بدون Downtime محسوس.
- خرابی یک SniDust → حذف آن IP از پاسخ‌های DNS ظرف ≤30s و بازگشت پس از بهبود.
- لاگ‌ها: CoreDNS و SniDust و Agent قابل مشاهده و عیب‌یابی باشند.

## تحویل‌ها (Deliverables)
- فایل‌های `docker-compose.yml` برای SniDust و CoreDNS.
- قواعد nftables با sets برای DNS و Proxy + اسکریپت init.
- Agent سبک (bash/python) برای:
  - Pull از Git و تولید `targets.override` و `99-custom.lst`.
  - Reload/Restart سرویس‌ها در صورت تغییر.
  - مدیریت setهای nftables (add/remove IP).
- اسکلت Control-Plane (FastAPI/Go) با روت‌های تعریف‌شده + README.
- systemd unit/service برای Agent و سرویس‌ها.
- README اجرایی: پیش‌نیازها، نصب، راه‌اندازی، تست، عیب‌یابی.

## الزامات زیرساخت
- 2× VPS داخل ایران (IPv4 پابلیک، پورت 53 باز).
- 2–3× VPS خارج (IPv4 پابلیک، 80/443 باز، 443/UDP مسدود).
- دسترسی SSH و sudo روی همه نودها.
- یک Git repo برای `domains.lst`.

## ورودی‌های لازم
- IP دو سرور ایران (DNS1, DNS2) و IP دو/سه سرور خارج (SniDust).
- URL مخزن Git برای `domains.lst`.
- سیاست آغازین: عمومی یا محدود به چند IP آزمایشی.
- لیست اولیه دامنه‌ها (پیشنهاد: شروع با Reddit).

## گام‌های اجرا
1) آماده‌سازی VPSها؛ نصب Docker/Compose، CoreDNS، nftables.  
2) استقرار SniDust خارج + فایروال (بستن 443/UDP).  
3) استقرار CoreDNS ایران + قالب بالا.  
4) راه‌اندازی Control-Plane و Agentها روی همه نودها.  
5) اتصال به Git و تست Sync/Reload.  
6) تست API برای افزودن/حذف IP مشتری و سناریوهای Failover.

---

وضعیت: این سند مرجع واحد اجرای پروژه است. پس از تأیید، کانفیگ‌ها، Agent و API مینیمال مطابق این پرامپت تولید و دیپلوی می‌شوند.
