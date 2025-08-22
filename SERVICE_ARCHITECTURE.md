# معماری سرویس سه‌بخشی (Controller + Site + App)

این سند مرجع زندهٔ معماری، قراردادهای API، دیتامدل، فرایند پرداخت، امنیت و نقشهٔ مسیر است. هدف: تبدیل «هستهٔ آمادهٔ dns-loki» به یک سرویس قابل فروش با وب‌سایت و اپ‌های چندسکویی.

---

## 1) نمای کلی سامانه

- بخش 1: Controller (موجود)
  - مدیریت نودها، دامنه‌ها، کلاینت‌ها (IPها)، فلگ‌های Enforcement. دامنه‌ها به‌صورت محلی در state کنترلر نگهداری و از طریق API داخلی مدیریت می‌شوند.
  - فایل‌ها/مسیرهای فعلی: `controller/api.py`, `controller/ui/index.html`, `agent/agent.py`, `scripts/install.sh`، قوانین nft در `nftables/`.
  - توصیهٔ انتشار: کنترلر روی شبکهٔ خصوصی/محافظت‌شده؛ دسترسی آن از «سایت» با یک توکن یا mTLS.

- بخش 2: Site (وب‌سایت + پنل ادمین/کاربر)
  - رابط بین کاربران/اپ و Controller، بدون اتصال مستقیم کلاینت‌ها به Controller.
  - ذخیره‌سازی داده‌های کاربری، خرید/اشتراک، IPهای کاربر، لیست نودها، لاگ‌ها.
  - انجام عملیات مدیریتی (ادمین): تعریف پلن، مدیریت کاربران، مدیریت دامنه‌ها (مستقیم از طریق API کنترلر)، همگام‌سازی کلاینت‌ها با Controller.

- بخش 3: App (Android, iOS, Windows + Web/PWA)
  - ورود با موبایل (OTP)، مشاهدهٔ DNSها، نمایش latency (در نسخهٔ native)، مدیریت IP (افزودن/حذف)، ارجاع به وب‌سایت برای خرید/تمدید.
  - نسخهٔ Web/PWA به‌صورت feature محدودتر (عدم اندازه‌گیری UDP مستقیم؛ نمایش توصیه/وضعیت).

ریپوها
- Repo A: dns-loki (همین ریپو – Controller/Agent).
- Repo B: dns-loki-site (Backend + Frontend وب‌سایت).
- Repo C: dns-loki-app (کراس‌پلتفرم).

---

## 2) پشتهٔ فناوری پیشنهادی

- Site Backend: Laravel 10+ (PHP 8.2+), MySQL 8، Eloquent ORM، Migrations/Seeders، Redis (کش/رات‌لیمیت/Queue)، Laravel Queue (مثلاً Redis) برای تسک‌های async: فراخوانی Controller، ارسال SMS، پردازش پرداخت.
- Site Frontend: Next.js 14 (React) + Tailwind + RTL پشتیبانی؛ پنل ادمین + پنل کاربر.
- Auth (Site): OTP با شماره موبایل؛ JWT Access/Refresh؛ نقش‌ها (admin, support, user).
- Payment: زرین‌پال (REST)، وبهوک/کالبک و Verify.
- SMS OTP: آداپتور (مثلاً Kavenegar/Ghasedak) + interface مشترک برای قابل‌تعویض بودن.
- App: Flutter (Android, iOS, Windows) + Web/PWA. Native می‌تواند UDP/Socket برای سنجش latency استفاده کند؛ Web محدودتر است.
- Observability: لاگ ساختاریافته، Sentry/ELK، health endpoints.

علت هم‌راستایی: Site با Laravel/MySQL مطابق ترجیح شما، Controller در Python/FastAPI باقی می‌ماند.

---

## 3) جداسازی مسئولیت‌ها و مرزبانی

- Controller
  - منبع حقیقت برای: وضعیت نودها، کلاینت‌های مجاز nftables، فلگ‌ها، CoreDNS/SNI Proxy کانفیگ‌های جاری، و «فهرست دامنه‌ها» در state محلی.
- Site
  - منبع حقیقت برای: کاربران، اشتراک‌ها/خریدها، IPهای کاربر (حداکثر ۲)، لیست نودهای قابل‌نمایش، دامنه‌های تجاری (مدیریت از پنل ادمین)، لایسنس/توکن.
  - Push به Controller: تغییرات IP کاربران (clients)، تغییر فلگ‌ها (در صورت نیاز)، CRUD دامنه‌ها و Trigger افزایش نسخه دامنه‌ها.
- App
  - فقط به Site وصل می‌شود؛ هیچ دسترسی مستقیم به Controller.

امنیت بین Site و Controller
- Shared token یا mTLS. توصیه: هدر `X-Internal-Token` با دوران کلید (rotation) + allowlist IP. این هدر اکنون در `controller/api.py` برای مسیرهای تغییردهنده فعال است (در نبود توکن، دسترسی آزاد برای سازگاری محیط توسعه).
- Rate-limit روی Controller برای مسیرهای تغییردهنده.

---

## 4) جریان‌های کلیدی (Flows)

- ورود کاربر (OTP)
  1) App/Site: شروع OTP با موبایل.
  2) Site: تولید کد، ارسال SMS، ذخیرهٔ کوتاه‌مدت (TTL).
  3) کاربر کد را تایید می‌کند؛ Site، JWT صادر می‌کند.

- مدیریت IP کاربر (حداکثر ۲ IP)
  1) کاربر IP اضافه/حذف می‌کند (Site API).
  2) Site اعتبارسنجی/محدودیت‌ها را اعمال می‌کند.
  3) Site تغییرات را به Controller push می‌کند (clients allow-list) و نتیجه را لاگ می‌کند.

- خرید/تمدید (زرین‌پال)
  1) Site: ایجاد Payment و Start پرداخت، ریدایرکت به زرین‌پال.
  2) Callback/Verify: تغییر وضعیت Payment، ایجاد/تمدید Subscription.
  3) اگر نیازمند Enforcement: Site اطمینان می‌دهد IPهای کاربر فعال و به Controller sync شده‌اند.

- مدیریت دامنه‌ها (ادمین)
  1) ادمین در Site دامنه اضافه/حذف/ویرایش می‌کند.
  2) Site تغییرات را مستقیم به Controller می‌فرستد: `POST /v1/domains` (تنظیم کامل)، یا `POST /v1/domains/add` (افزودن تکی)، یا `DELETE /v1/domains/{domain}` (حذف تکی).
  3) Site سپس `POST /v1/domains/sync` را برای افزایش نسخه دامنه‌ها صدا می‌زند تا Agentها همگام شوند.

- مدیریت نودها (ادمین)
  1) ادمین DNS/Proxy جدید را در Site ثبت می‌کند (نمایش برای کاربر).
  2) Site تضمین می‌کند نود در Controller نیز وجود دارد (`/v1/nodes` add اگر نبود).

---

## 5) قراردادهای API (نمونه‌ها)

App ↔ Site (عمومی)
- شروع OTP
```http
POST /api/v1/auth/start-otp
Content-Type: application/json
{
  "mobile": "09xxxxxxxxx"
}
```
- تایید OTP و دریافت توکن
```http
POST /api/v1/auth/verify-otp
Content-Type: application/json
{
  "mobile": "09xxxxxxxxx",
  "code": "123456"
}
```
- لیست DNSها (قابل نمایش به کاربر)
```http
GET /api/v1/dns/nodes
Authorization: Bearer <JWT>
```
- دریافت IPهای کاربر
```http
GET /api/v1/user/ips
Authorization: Bearer <JWT>
```
- افزودن IP (حداکثر ۲)
```http
POST /api/v1/user/ips
Authorization: Bearer <JWT>
Content-Type: application/json
{
  "ip": "203.0.113.10"
}
```
- حذف IP
```http
DELETE /api/v1/user/ips/{ip}
Authorization: Bearer <JWT>
```
- دریافت پلن‌ها
```http
GET /api/v1/plans
```
- شروع پرداخت
```http
POST /api/v1/payments/start
Authorization: Bearer <JWT>
Content-Type: application/json
{
  "plan_id": "basic-monthly"
}
```
- Verify پرداخت (کالبک داخلی هم دارد)
```http
GET /api/v1/payments/verify?Authority=...&Status=...
```
- لینک‌های دانلود اپ
```http
GET /api/v1/app/download-links
```

Site ↔ Controller (داخلی، امن)
- همگام‌سازی IPها (clients)
  - افزودن/به‌روزرسانی (upsert) هر IP کاربر با scope موردنیاز:
```http
POST http://<CONTROLLER_IP>:8080/v1/clients
Content-Type: application/json
X-Internal-Token: <SECRET>
{
  "ip": "203.0.113.10",
  "note": "user:<USER_ID>",
  "scope": ["dns", "proxy"]
}
```
  - حذف IP:
```http
DELETE http://<CONTROLLER_IP>:8080/v1/clients/203.0.113.10
X-Internal-Token: <SECRET>
```
- فلگ‌ها (در صورت نیاز)
```http
POST http://<CONTROLLER_IP>:8080/v1/flags
Content-Type: application/json
X-Internal-Token: <SECRET>
{
  "enforce_dns_clients": true
}
```
- ثبت نودها (اگر نبود)
```http
POST http://<CONTROLLER_IP>:8080/v1/nodes
Content-Type: application/json
X-Internal-Token: <SECRET>
{
  "ip": "185.84.158.34",
  "role": "dns",
  "enabled": true
}
```
- دامنه‌ها (CRUD مستقیم روی Controller):
```http
POST http://<CONTROLLER_IP>:8080/v1/domains
Content-Type: application/json
X-Internal-Token: <SECRET>
{
  "domains": ["example.com", "foo.bar"]
}
```
```http
POST http://<CONTROLLER_IP>:8080/v1/domains/add
Content-Type: application/json
X-Internal-Token: <SECRET>
{
  "domain": "baz.example"
}
```
```http
DELETE http://<CONTROLLER_IP>:8080/v1/domains/baz.example
X-Internal-Token: <SECRET>
```
```http
POST http://<CONTROLLER_IP>:8080/v1/domains/sync
X-Internal-Token: <SECRET>
```

یادداشت: Endpoint حذف کلاینت (`DELETE /v1/clients/{ip}`) موجود است.

---

## 6) دیتامدل (Site / MySQL)

- users: id, mobile(unique), status, created_at
- otp_codes: id, mobile, code(hash), expires_at, attempts, created_at
- plans: id(slug), name, duration_days, price_amount, price_currency, max_ips (پیش‌فرض 2), active
- subscriptions: id, user_id, plan_id, starts_at, ends_at, status(active, expired, canceled)
- payments: id, user_id, plan_id, amount, authority, ref_id, status(init, pending, paid, failed), created_at, paid_at
- user_ips: id, user_id, ip, verified(bool), created_at
- dns_nodes: id, ip, region, label, shown(bool), priority, created_at
- proxy_nodes: id, ip, region, label, shown(bool), priority, created_at
- domains: id, name, enabled, source(repo/manual), created_at
- audit_logs: id, actor(user/admin/system), action, details(json), created_at

کلیدها/محدودیت‌ها
- محدودیت یکتا برای (user_id, ip) در `user_ips`.
- حداکثر ۲ IP برای هر کاربر (constraint سطح اپ + چک DB/trigger).
- ایندکس روی mobile، authority، ref_id.

یادداشت پیاده‌سازی در Laravel:
- Migrations/Seeders برای جداول فوق، Modelهای Eloquent متناظر.
- Job/Queue برای SMS و همگام‌سازی با Controller.

---

## 7) پرداخت زرین‌پال (Flow)

- Start
```http
POST /api/v1/payments/start
{
  "plan_id": "basic-monthly"
}
```
  - Site: ایجاد رکورد payment(pending) + درخواست Zarinpal + دریافت Authority + redirect URL.
- Callback (کاربر → سایت)
```
GET /api/v1/payments/callback?Authority=...&Status=...
```
  - Site: Verify با Zarinpal؛ در صورت موفق، `ref_id` ذخیره، payment=paid، ایجاد/تمدید subscription، رسید.
- Webhook (اختیاری): برای اطمینان و سازگاری خطا.

پیکربندی
- ENV: `ZARINPAL_MERCHANT_ID`, `ZARINPAL_CALLBACK_URL`.
- Log کامل تبادلات و مدیریت خطا/timeout.

---

## 8) اندازه‌گیری Latency در App

- Native (Flutter):
  - ارسال DNS query سبک (A برای یک دامنهٔ تست) به هر DNS و اندازه‌گیری RTT (UDP). Timeout/تعداد تکرار.
  - نمایش میانگین/مین/ماکس و توصیه.
- Web/PWA:
  - محدودیت Web در UDP؛ MVP: نمایش وضعیت/پیشنهاد براساس منطقه/سیاست.
  - آینده: اضافه‌کردن HTTP health endpoint سبک روی DNSها برای اندازه‌گیری TCP/HTTP RTT (در صورت تایید امنیتی) یا DoH Gateway.

---

## 9) امنیت و انطباق

- Site ↔ Controller: mTLS یا Shared Token + allowlist IP + Rate limit. پشتیبانی از هدر `X-Internal-Token` یا `Authorization: Bearer <token>` در `controller/api.py` برای مسیرهای تغییردهنده افزوده شد.
- OTP: rate-limit (درخواست/ساعت)، قفل موقت پس از چند تلاش.
- JWT: انقضا کوتاه + Refresh + revoke در تغییرات حساس.
- IP Management: Audit trail هر تغییر؛ حفاظت در برابر abuse (limit تغییرات روزانه).
- Payments: ضد تکرار (idempotency key)، صحه‌گذاری مبلغ/پلن.
- داده‌ها: PII حداقلی (موبایل، IP)، رمزنگاری در حال سکون (PG encryption-at-rest اختیاراً) و در انتقال (HTTPS).

---

## 10) استقرار و DevOps

- Site: Dockerized (backend, frontend, db, redis). محیط staging/production. اجرا با `php-fpm` + Nginx.
- Controller: پشتیبانی از token check برای درخواست‌های داخلی Site اعمال شده است (`INTERNAL_TOKEN`).
- CI/CD: تست واحد/یکپارچه (PHPUnit)، `php artisan migrate --force` در استقرار، اسکن امنیتی.
- مانیتورینگ: health, metrics, logs. هشدار برای خطاهای پرداخت/OTP/Sync Controller.

---

## 11) نقشهٔ مسیر (Milestones)

MVP-1 (2–3 هفته)
- Auth OTP + پنل کاربر مینیمال.
- Plan/Payment (زرین‌پال) + اشتراک.
- مدیریت IP کاربر (حداکثر 2) + Sync به Controller (افزودن/حذف).
- پنل ادمین: مدیریت کاربران/پلن‌ها/نودها/دامنه‌ها (مدیریت مستقیم روی Controller) + Trigger sync.
- App: ورود، نمایش DNSها، مدیریت IP (بدون latency).

MVP-2 (1–2 هفته)
- اندازه‌گیری latency در اپ Native.
- بهبودهای UI/UX، اعلان‌ها، گزارش‌ها.
- بهبود امنیت (mTLS Site↔Controller)، rate-limit، لاگ کامل.

GA
- برنامه ارجاع، کد تخفیف، صورت‌حساب PDF.
- وضعیت/health صفحهٔ عمومی، پشتیبانی تیکتی.

---

## 12) وابستگی‌ها و TODO ها

- [x] Endpoint حذف کلاینت در Controller: `DELETE /v1/clients/{ip}` موجود است.
- [x] توکن داخلی و اعتبارسنجی در Controller برای مسیرهای حساس افزوده شد (`X-Internal-Token`/Bearer).
- [ ] ریپوی `dns-loki-site` و `dns-loki-app` ایجاد و CI/CD پایه.
- [ ] Site: پیاده‌سازی Backend Laravel + MySQL با OTP، JWT، پرداخت زرین‌پال، و API Gateway به Controller.
- [ ] تصمیم نهایی دربارهٔ health/latency وب (HTTP/DoH) روی DNSها.

---

## 13) پیوست‌ها و ملاحظات

- محدودیت Secondary DNS سمت کاربر: آموزش در سایت برای تنظیم تنها DNSهای ارائه‌شده.
- HTTP/3: مسدودسازی UDP/443 در Proxy برای اجبار HTTP/2 (از قبل در `nftables/proxy.nft`).
- تداوم سرویس در شرایط مسدودسازی رجیستری‌ها: fallback CoreDNS در installer آماده است.
