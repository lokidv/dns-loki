#!/bin/bash
#
# DNS-Loki Deployment Script
# Deploy the refactored DNS-Loki controller to production server
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
DEPLOY_DIR="/opt/dns-proxy"
BACKUP_DIR="/opt/dns-proxy/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo -e "${GREEN}DNS-Loki Deployment Script v2.0${NC}"
echo "================================"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

# Create backup directory
echo -e "${YELLOW}Creating backup...${NC}"
mkdir -p "$BACKUP_DIR"
if [ -d "$DEPLOY_DIR/controller" ]; then
    cp -ra "$DEPLOY_DIR/controller" "$BACKUP_DIR/controller_$TIMESTAMP"
    echo -e "${GREEN}✓ Backup created: $BACKUP_DIR/controller_$TIMESTAMP${NC}"
fi

# Stop services
echo -e "${YELLOW}Stopping services...${NC}"
systemctl stop dns-proxy-controller || true
echo -e "${GREEN}✓ Services stopped${NC}"

# Create deployment directories
echo -e "${YELLOW}Creating deployment directories...${NC}"
mkdir -p "$DEPLOY_DIR/controller"
mkdir -p "$DEPLOY_DIR/controller/core"
mkdir -p "$DEPLOY_DIR/controller/services"
mkdir -p "$DEPLOY_DIR/controller/models"
mkdir -p "$DEPLOY_DIR/controller/routers"
mkdir -p "$DEPLOY_DIR/controller/ui"
mkdir -p "$DEPLOY_DIR/logs"
mkdir -p "$DEPLOY_DIR/data"

# Copy new files
echo -e "${YELLOW}Deploying new controller files...${NC}"

# Copy core modules
cp -f controller/core/*.py "$DEPLOY_DIR/controller/core/" 2>/dev/null || true

# Copy services
cp -f controller/services/*.py "$DEPLOY_DIR/controller/services/" 2>/dev/null || true

# Copy models
cp -f controller/models/*.py "$DEPLOY_DIR/controller/models/" 2>/dev/null || true

# Copy routers
cp -f controller/routers/*.py "$DEPLOY_DIR/controller/routers/" 2>/dev/null || true

# Copy main files
cp -f controller/main.py "$DEPLOY_DIR/controller/"
cp -f controller/__init__.py "$DEPLOY_DIR/controller/"
cp -f controller/api.py "$DEPLOY_DIR/controller/"  # Keep old API for compatibility

# Copy UI files
cp -rf controller/ui/* "$DEPLOY_DIR/controller/ui/" 2>/dev/null || true

# Copy requirements
cp -f requirements.txt "$DEPLOY_DIR/controller/"

# Copy configuration files
if [ ! -f "$DEPLOY_DIR/controller/.env" ]; then
    echo -e "${YELLOW}Creating default .env file...${NC}"
    cat > "$DEPLOY_DIR/controller/.env" <<EOF
# DNS-Loki Controller Configuration
SECRET_KEY=$(openssl rand -hex 32)
DATABASE_URL=sqlite+aiosqlite:///$DEPLOY_DIR/data/dnsloki.db
REDIS_URL=redis://localhost:6379/0
LOG_LEVEL=INFO
DEBUG=False
HOST=0.0.0.0
PORT=8000
CORS_ORIGINS=["*"]
ACCESS_TOKEN_EXPIRE_MINUTES=30
ALGORITHM=HS256
EOF
    chmod 600 "$DEPLOY_DIR/controller/.env"
fi

# Setup Python virtual environment
echo -e "${YELLOW}Setting up Python environment...${NC}"
if [ ! -d "$DEPLOY_DIR/controller/venv" ]; then
    python3 -m venv "$DEPLOY_DIR/controller/venv"
fi

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
"$DEPLOY_DIR/controller/venv/bin/pip" install --upgrade pip
"$DEPLOY_DIR/controller/venv/bin/pip" install -r "$DEPLOY_DIR/controller/requirements.txt"

# Create systemd service if not exists
if [ ! -f /etc/systemd/system/dns-proxy-controller.service ]; then
    echo -e "${YELLOW}Creating systemd service...${NC}"
    cat > /etc/systemd/system/dns-proxy-controller.service <<EOF
[Unit]
Description=DNS-Loki Controller
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$DEPLOY_DIR/controller
Environment="PATH=$DEPLOY_DIR/controller/venv/bin"
ExecStart=$DEPLOY_DIR/controller/venv/bin/python -m uvicorn controller.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
fi

# Set permissions
echo -e "${YELLOW}Setting permissions...${NC}"
chown -R root:root "$DEPLOY_DIR/controller"
chmod -R 755 "$DEPLOY_DIR/controller"
chmod -R 777 "$DEPLOY_DIR/logs"
chmod -R 777 "$DEPLOY_DIR/data"

# Initialize database
echo -e "${YELLOW}Initializing database...${NC}"
"$DEPLOY_DIR/controller/venv/bin/python" -c "
import asyncio
import sys
sys.path.insert(0, '$DEPLOY_DIR/controller')
from controller.services.database_service import DatabaseService

async def init_db():
    db = DatabaseService()
    await db.initialize()
    print('Database initialized')

asyncio.run(init_db())
" || true

# Start services
echo -e "${YELLOW}Starting services...${NC}"
systemctl enable dns-proxy-controller
systemctl start dns-proxy-controller

# Wait for service to start
sleep 3

# Check service status
echo -e "${YELLOW}Checking service status...${NC}"
if systemctl is-active --quiet dns-proxy-controller; then
    echo -e "${GREEN}✓ DNS-Loki Controller is running${NC}"
else
    echo -e "${RED}✗ DNS-Loki Controller failed to start${NC}"
    echo "Check logs with: journalctl -u dns-proxy-controller -n 50"
    exit 1
fi

# Show service info
echo ""
echo -e "${GREEN}Deployment completed successfully!${NC}"
echo "================================"
echo "Controller URL: http://$(hostname -I | awk '{print $1}'):8000"
echo "API Documentation: http://$(hostname -I | awk '{print $1}'):8000/api/docs"
echo ""
echo "Commands:"
echo "  View logs: journalctl -u dns-proxy-controller -f"
echo "  Restart: systemctl restart dns-proxy-controller"
echo "  Status: systemctl status dns-proxy-controller"
echo ""
echo "Default credentials (if first run):"
echo "  Username: admin"
echo "  Password: admin123"
echo "  ${YELLOW}Please change the password after first login!${NC}"
