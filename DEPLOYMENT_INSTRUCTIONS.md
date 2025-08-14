# DNS-Loki v2.0 Deployment Instructions

## Prerequisites
- Ubuntu 20.04+ or Debian 11+ server
- Python 3.8 or higher
- Root access
- At least 2GB RAM
- 10GB free disk space

## Quick Deployment

### 1. Upload Files to Server
```bash
# From your local machine
scp -r dns-loki/ root@your-server:/root/
```

### 2. Run Deployment Script
```bash
# On the server
cd /root/dns-loki
chmod +x deploy.sh
./deploy.sh
```

## Manual Deployment Steps

### 1. Backup Existing Installation
```bash
# Create backup directory
mkdir -p /opt/dns-proxy/backups
cp -ra /opt/dns-proxy/controller /opt/dns-proxy/backups/controller_$(date +%Y%m%d_%H%M%S)
```

### 2. Stop Services
```bash
systemctl stop dns-proxy-controller
```

### 3. Install System Dependencies
```bash
apt update
apt install -y python3 python3-pip python3-venv git nginx redis-server
```

### 4. Copy New Files
```bash
# Copy controller files
cp -r controller/* /opt/dns-proxy/controller/

# Copy requirements
cp requirements.txt /opt/dns-proxy/controller/

# Set permissions
chmod -R 755 /opt/dns-proxy/controller
```

### 5. Setup Python Environment
```bash
cd /opt/dns-proxy/controller

# Create virtual environment
python3 -m venv venv

# Activate and install dependencies
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 6. Configure Environment
```bash
# Create .env file
cat > /opt/dns-proxy/controller/.env <<EOF
SECRET_KEY=$(openssl rand -hex 32)
DATABASE_URL=sqlite+aiosqlite:///opt/dns-proxy/data/dnsloki.db
REDIS_URL=redis://localhost:6379/0
LOG_LEVEL=INFO
DEBUG=False
HOST=0.0.0.0
PORT=8000
CORS_ORIGINS=["*"]
ACCESS_TOKEN_EXPIRE_MINUTES=30
ALGORITHM=HS256
EOF

chmod 600 /opt/dns-proxy/controller/.env
```

### 7. Initialize Database
```bash
cd /opt/dns-proxy/controller
./venv/bin/python -c "
import asyncio
from controller.services.database_service import DatabaseService

async def init():
    db = DatabaseService()
    await db.initialize()
    print('Database initialized')

asyncio.run(init())
"
```

### 8. Migrate Existing Data
```bash
# If you have existing data
cd /root/dns-loki
chmod +x migrate.py
./migrate.py
```

### 9. Setup Systemd Service
```bash
cat > /etc/systemd/system/dns-proxy-controller.service <<EOF
[Unit]
Description=DNS-Loki Controller
After=network.target redis.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/dns-proxy/controller
Environment="PATH=/opt/dns-proxy/controller/venv/bin"
ExecStart=/opt/dns-proxy/controller/venv/bin/python -m uvicorn controller.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable dns-proxy-controller
```

### 10. Start Services
```bash
# Start Redis
systemctl start redis-server
systemctl enable redis-server

# Start Controller
systemctl start dns-proxy-controller

# Check status
systemctl status dns-proxy-controller
```

## Post-Deployment Tasks

### 1. Verify Installation
```bash
# Check if service is running
curl http://localhost:8000/api/v1/monitoring/health

# Check logs
journalctl -u dns-proxy-controller -n 50
```

### 2. Access Web UI
Open in browser:
```
http://your-server-ip:8000
```

Default credentials:
- Username: `admin`
- Password: `admin123`

**⚠️ IMPORTANT: Change the default password immediately!**

### 3. Configure Firewall
```bash
# Allow controller port
ufw allow 8000/tcp

# Allow DNS (if this is a DNS node)
ufw allow 53/udp
ufw allow 53/tcp

# Allow SNI Proxy (if this is a proxy node)
ufw allow 443/tcp
```

### 4. Setup Nginx Reverse Proxy (Optional)
```bash
cat > /etc/nginx/sites-available/dns-loki <<EOF
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

ln -s /etc/nginx/sites-available/dns-loki /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

### 5. Setup SSL with Let's Encrypt (Optional)
```bash
apt install -y certbot python3-certbot-nginx
certbot --nginx -d your-domain.com
```

## Testing

### 1. Run Test Script
```bash
cd /root/dns-loki
chmod +x test_deployment.sh
./test_deployment.sh
```

### 2. Manual API Tests
```bash
# Login
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123" \
  | jq -r .access_token)

# Test API endpoints
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/nodes
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/clients
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/config
```

### 3. Run Unit Tests
```bash
cd /opt/dns-proxy/controller
./venv/bin/pytest tests/ -v
```

## Troubleshooting

### Service Won't Start
```bash
# Check logs
journalctl -u dns-proxy-controller -n 100

# Check Python errors
cd /opt/dns-proxy/controller
./venv/bin/python -m controller.main

# Check permissions
ls -la /opt/dns-proxy/
```

### Database Issues
```bash
# Reset database
rm -f /opt/dns-proxy/data/dnsloki.db
cd /opt/dns-proxy/controller
./venv/bin/python -c "
import asyncio
from controller.services.database_service import DatabaseService
asyncio.run(DatabaseService().initialize())
"
```

### Port Already in Use
```bash
# Find process using port 8000
lsof -i :8000

# Kill process
kill -9 <PID>
```

### Redis Connection Error
```bash
# Check Redis status
systemctl status redis-server

# Test Redis connection
redis-cli ping
```

## Monitoring

### Check Logs
```bash
# Controller logs
journalctl -u dns-proxy-controller -f

# Application logs
tail -f /opt/dns-proxy/logs/controller.log
```

### System Resources
```bash
# Check memory usage
free -h

# Check disk usage
df -h

# Check CPU usage
top
```

### Service Health
```bash
# Health endpoint
curl http://localhost:8000/api/v1/monitoring/health

# Metrics endpoint
curl http://localhost:8000/api/v1/monitoring/metrics
```

## Backup & Restore

### Backup
```bash
# Create backup
tar -czf dns-loki-backup-$(date +%Y%m%d).tar.gz \
  /opt/dns-proxy/controller \
  /opt/dns-proxy/data \
  /opt/dns-proxy/logs
```

### Restore
```bash
# Stop services
systemctl stop dns-proxy-controller

# Extract backup
tar -xzf dns-loki-backup-20240115.tar.gz -C /

# Start services
systemctl start dns-proxy-controller
```

## Security Recommendations

1. **Change default passwords immediately**
2. **Use strong passwords** (minimum 12 characters)
3. **Enable firewall** and restrict access
4. **Use HTTPS** with valid SSL certificates
5. **Regular backups** (daily recommended)
6. **Monitor logs** for suspicious activity
7. **Keep system updated** with security patches
8. **Use SSH keys** instead of passwords
9. **Implement rate limiting** on API
10. **Regular security audits**

## Support

For issues or questions:
1. Check logs: `journalctl -u dns-proxy-controller -n 100`
2. Review API documentation: `/API_DOCUMENTATION.md`
3. Run diagnostics: `./test_deployment.sh`

## Version Information
- DNS-Loki Controller: v2.0.0
- Required Python: 3.8+
- API Version: v1
- Database: SQLite/PostgreSQL
- Cache: Redis
