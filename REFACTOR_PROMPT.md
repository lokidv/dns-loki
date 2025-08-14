# پرامپت بهبود و بازسازی پروژه DNS-Loki

## هدف کلی
بهبود کیفیت کد، امنیت، UI و معماری پروژه dns-loki بدون خراب کردن عملکرد فعلی سیستم.

## اولویت‌های بهبود

### 1. تمیزی و سازماندهی کد (Code Quality)
- **هدف**: کد خوانا، قابل نگهداری و استاندارد
- **اقدامات مورد نیاز**:
  - جداسازی منطق کسب‌وکار از API endpoints
  - ایجاد کلاس‌های Service برای منطق پیچیده
  - حذف کدهای تکراری (DRY principle)
  - اضافه کردن type hints و docstrings
  - استفاده از design patterns مناسب
  - بهبود error handling و logging
  - ایجاد configuration management مرکزی

### 2. بهبود منطق سرور و کانفیگ (Server Logic & Configuration)
- **هدف**: معماری قابل اعتماد و قابل توسعه
- **اقدامات مورد نیاز**:
  - جداسازی configuration از کد
  - ایجاد validation برای تمام configs
  - بهبود state management بین controller و agents
  - اضافه کردن health checks و monitoring
  - بهبود sync mechanism بین نودها
  - پیاده‌سازی graceful shutdown
  - اضافه کردن retry logic و circuit breaker

### 3. بهبود UI کنترل پنل (Control Panel Enhancement)
- **هدف**: رابط کاربری مدرن، responsive و کاربرپسند
- **اقدامات مورد نیاز**:
  - طراحی مجدد با framework مدرن (Vue.js/React یا vanilla ES6+)
  - اضافه کردن real-time updates با WebSocket
  - بهبود UX برای مدیریت نودها
  - اضافه کردن dashboard با metrics و charts
  - پیاده‌سازی dark/light theme
  - اضافه کردن notification system
  - بهبود mobile responsiveness
  - اضافه کردن bulk operations

### 4. تقویت امنیت (Security Enhancement)
- **هدف**: امنیت enterprise-grade
- **اقدامات مورد نیاز**:
  - پیاده‌سازی authentication و authorization
  - اضافه کردن JWT token management
  - اعمال rate limiting
  - پیاده‌سازی HTTPS اجباری
  - اضافه کردن input validation و sanitization
  - پیاده‌سازی RBAC (Role-Based Access Control)
  - اضافه کردن audit logging
  - بهبود SSH key management
  - پیاده‌سازی API key authentication
  - اضافه کردن CORS policy

### 5. طراحی API استاندارد (API Design)
- **هدف**: RESTful API کامل و مستندسازی شده
- **اقدامات مورد نیاز**:
  - طراحی مجدد API endpoints با RESTful principles
  - اضافه کردن OpenAPI/Swagger documentation
  - پیاده‌سازی API versioning
  - اضافه کردن pagination برای list endpoints
  - پیاده‌سازی filtering و sorting
  - اضافه کردن bulk operations API
  - پیاده‌سازی webhook support
  - اضافه کردن API rate limiting
  - ایجاد SDK برای زبان‌های مختلف

## معماری هدف

### Backend Structure
```
dns-loki/
├── controller/
│   ├── api/
│   │   ├── __init__.py
│   │   ├── auth.py          # Authentication & Authorization
│   │   ├── nodes.py         # Node management endpoints
│   │   ├── config.py        # Configuration endpoints
│   │   ├── monitoring.py    # Health & metrics endpoints
│   │   └── webhooks.py      # Webhook endpoints
│   ├── services/
│   │   ├── __init__.py
│   │   ├── node_service.py  # Node business logic
│   │   ├── config_service.py # Config management
│   │   ├── ssh_service.py   # SSH operations
│   │   └── sync_service.py  # Synchronization logic
│   ├── models/
│   │   ├── __init__.py
│   │   ├── node.py          # Node data models
│   │   ├── config.py        # Configuration models
│   │   └── user.py          # User & auth models
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py        # App configuration
│   │   ├── security.py      # Security utilities
│   │   ├── database.py      # Database connection
│   │   └── exceptions.py    # Custom exceptions
│   └── main.py              # FastAPI app initialization
├── agent/
│   ├── core/
│   │   ├── __init__.py
│   │   ├── agent.py         # Main agent logic
│   │   ├── config.py        # Agent configuration
│   │   └── services.py      # Service management
│   └── utils/
│       ├── __init__.py
│       ├── docker.py        # Docker operations
│       └── network.py       # Network utilities
└── shared/
    ├── __init__.py
    ├── models.py            # Shared data models
    ├── constants.py         # Shared constants
    └── utils.py             # Shared utilities
```

### Frontend Structure
```
controller/ui/
├── src/
│   ├── components/
│   │   ├── Dashboard.js
│   │   ├── NodeManager.js
│   │   ├── ConfigPanel.js
│   │   └── MonitoringPanel.js
│   ├── services/
│   │   ├── api.js           # API client
│   │   ├── auth.js          # Authentication
│   │   └── websocket.js     # Real-time updates
│   ├── utils/
│   │   ├── helpers.js
│   │   └── constants.js
│   ├── styles/
│   │   ├── main.css
│   │   └── themes.css
│   └── main.js
├── assets/
└── index.html
```

## مراحل پیاده‌سازی

### فاز 1: پایه‌گذاری (Foundation)
1. ایجاد ساختار جدید پروژه
2. تنظیم configuration management
3. پیاده‌سازی logging و monitoring
4. ایجاد test framework

### فاز 2: Backend Refactoring
1. جداسازی business logic از API
2. پیاده‌سازی service layer
3. بهبود error handling
4. اضافه کردن authentication

### فاز 3: API Enhancement
1. طراحی مجدد endpoints
2. اضافه کردن documentation
3. پیاده‌سازی rate limiting
4. اضافه کردن API versioning

### فاز 4: Security Implementation
1. پیاده‌سازی JWT authentication
2. اضافه کردن RBAC
3. تقویت input validation
4. پیاده‌سازی audit logging

### فاز 5: Frontend Modernization
1. طراحی مجدد UI
2. پیاده‌سازی real-time updates
3. اضافه کردن responsive design
4. بهبود UX

### فاز 6: Testing & Documentation
1. اضافه کردن unit tests
2. پیاده‌سازی integration tests
3. ایجاد API documentation
4. نوشتن user manual

## ملاحظات مهم

### حفظ عملکرد فعلی
- تمام تغییرات باید backward compatible باشند
- قبل از هر تغییر، backup از state فعلی تهیه شود
- پیاده‌سازی تدریجی با feature flags
- تست کامل در محیط staging

### Performance Considerations
- بهینه‌سازی database queries
- اضافه کردن caching layer
- پیاده‌سازی connection pooling
- بهبود memory management

### Monitoring & Observability
- اضافه کردن metrics collection
- پیاده‌سازی health checks
- ایجاد alerting system
- اضافه کردن distributed tracing

## خروجی مورد انتظار

### کیفیت کد
- Code coverage > 80%
- Linting score > 9/10
- Zero security vulnerabilities
- Comprehensive documentation

### Performance
- API response time < 200ms
- UI load time < 2s
- Memory usage optimized
- CPU usage minimized

### Security
- All endpoints authenticated
- Input validation 100%
- Audit logging complete
- Vulnerability scan passed

### User Experience
- Modern, responsive UI
- Real-time updates
- Intuitive navigation
- Mobile-friendly design

## نکات تکمیلی

1. **تست**: هر feature جدید باید unit test و integration test داشته باشد
2. **Documentation**: تمام API endpoints باید مستندسازی شوند
3. **Migration**: برنامه‌ای برای migration از نسخه فعلی به نسخه جدید
4. **Rollback**: امکان بازگشت سریع در صورت مشکل
5. **Monitoring**: نظارت مستمر بر performance و errors

این پرامپت راهنمای کاملی برای بهبود تدریجی و اصولی پروژه dns-loki ارائه می‌دهد که عملکرد فعلی را حفظ می‌کند و در عین حال کیفیت، امنیت و قابلیت استفاده را به شدت بهبود می‌بخشد.
