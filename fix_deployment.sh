#!/bin/bash

# DNS-Loki Controller Deployment Fix Script
# This script fixes the import issues and restarts the controller with the new structure

set -e

echo "DNS-Loki Controller Fix Script"
echo "=============================="

# Stop the old controller
echo "Stopping old controller..."
systemctl stop dns-proxy-controller 2>/dev/null || true
pkill -f "uvicorn api:app" 2>/dev/null || true
pkill -f "uvicorn main:app" 2>/dev/null || true

# Copy the runner script
echo "Installing runner script..."
cp /root/dns-loki/controller/run.py /opt/dns-proxy/controller/run.py
chmod +x /opt/dns-proxy/controller/run.py

# Update the systemd service
echo "Updating systemd service..."
cat > /etc/systemd/system/dns-proxy-controller.service << 'EOF'
[Unit]
Description=DNS-Loki Controller Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/dns-proxy/controller
Environment="PATH=/opt/dns-proxy/controller/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/opt/dns-proxy/controller/venv/bin/python /opt/dns-proxy/controller/run.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
echo "Reloading systemd..."
systemctl daemon-reload

# Start the new controller
echo "Starting controller..."
systemctl start dns-proxy-controller
systemctl enable dns-proxy-controller

# Check status
echo ""
echo "Checking service status..."
sleep 3
systemctl status dns-proxy-controller --no-pager

# Check if port 8000 is listening
echo ""
echo "Checking port 8000..."
ss -tlnp | grep 8000 || netstat -tlnp | grep 8000 || echo "Port 8000 not listening yet"

echo ""
echo "Fix completed!"
echo "Access the panel at: http://$(hostname -I | awk '{print $1}'):8000"
echo ""
echo "To check logs: journalctl -u dns-proxy-controller -f"
