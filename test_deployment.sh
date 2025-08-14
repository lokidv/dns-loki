#!/bin/bash
#
# DNS-Loki Deployment Test Script
# Tests the deployment to ensure everything is working correctly
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
API_URL="http://localhost:8000"
DEFAULT_USER="admin"
DEFAULT_PASS="admin123"

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}DNS-Loki Deployment Test Suite${NC}"
echo -e "${BLUE}================================${NC}\n"

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo -n "Testing $test_name... "
    
    if eval "$test_command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASSED${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
}

# 1. Check if service is running
echo -e "${YELLOW}1. Service Status Tests${NC}"
run_test "Controller service" "systemctl is-active --quiet dns-proxy-controller"
run_test "Redis service" "systemctl is-active --quiet redis-server || systemctl is-active --quiet redis"

# 2. Check API health
echo -e "\n${YELLOW}2. API Health Tests${NC}"
run_test "Health endpoint" "curl -f -s $API_URL/api/v1/monitoring/health"
run_test "API docs available" "curl -f -s $API_URL/api/docs > /dev/null"

# 3. Test authentication
echo -e "\n${YELLOW}3. Authentication Tests${NC}"
echo -n "Testing login... "
TOKEN=$(curl -s -X POST $API_URL/api/v1/auth/login \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=$DEFAULT_USER&password=$DEFAULT_PASS" \
    2>/dev/null | python3 -c "import sys, json; print(json.load(sys.stdin).get('access_token', ''))" 2>/dev/null)

if [ -n "$TOKEN" ]; then
    echo -e "${GREEN}✓ PASSED${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ FAILED${NC}"
    ((TESTS_FAILED++))
    echo -e "${RED}Cannot continue without authentication. Exiting.${NC}"
    exit 1
fi

# 4. Test API endpoints
echo -e "\n${YELLOW}4. API Endpoint Tests${NC}"
run_test "GET /nodes" "curl -f -s -H 'Authorization: Bearer $TOKEN' $API_URL/api/v1/nodes"
run_test "GET /clients" "curl -f -s -H 'Authorization: Bearer $TOKEN' $API_URL/api/v1/clients"
run_test "GET /config" "curl -f -s -H 'Authorization: Bearer $TOKEN' $API_URL/api/v1/config"
run_test "GET /sync/status" "curl -f -s -H 'Authorization: Bearer $TOKEN' $API_URL/api/v1/sync/status"
run_test "GET /monitoring/status" "curl -f -s -H 'Authorization: Bearer $TOKEN' $API_URL/api/v1/monitoring/status"
run_test "GET /auth/me" "curl -f -s -H 'Authorization: Bearer $TOKEN' $API_URL/api/v1/auth/me"

# 5. Test database connectivity
echo -e "\n${YELLOW}5. Database Tests${NC}"
echo -n "Testing database connection... "
if python3 -c "
import sys
sys.path.insert(0, '/opt/dns-proxy/controller')
import asyncio
from controller.services.database_service import DatabaseService

async def test():
    try:
        db = DatabaseService()
        await db.initialize()
        await db.close()
        return True
    except:
        return False

result = asyncio.run(test())
sys.exit(0 if result else 1)
" 2>/dev/null; then
    echo -e "${GREEN}✓ PASSED${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ FAILED${NC}"
    ((TESTS_FAILED++))
fi

# 6. Test Redis connectivity
echo -e "\n${YELLOW}6. Cache Tests${NC}"
run_test "Redis connection" "redis-cli ping | grep -q PONG"

# 7. Check file permissions
echo -e "\n${YELLOW}7. File Permission Tests${NC}"
run_test "Controller directory" "[ -d /opt/dns-proxy/controller ]"
run_test "Data directory" "[ -d /opt/dns-proxy/data ]"
run_test "Logs directory" "[ -d /opt/dns-proxy/logs ]"
run_test "Virtual environment" "[ -d /opt/dns-proxy/controller/venv ]"

# 8. Check Python dependencies
echo -e "\n${YELLOW}8. Dependency Tests${NC}"
echo -n "Testing Python packages... "
if /opt/dns-proxy/controller/venv/bin/python -c "
import fastapi
import uvicorn
import pydantic
import sqlalchemy
import redis
import paramiko
import jwt
print('All packages imported successfully')
" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ PASSED${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ FAILED${NC}"
    ((TESTS_FAILED++))
fi

# 9. Test WebSocket connection
echo -e "\n${YELLOW}9. WebSocket Tests${NC}"
echo -n "Testing WebSocket endpoint... "
if python3 -c "
import asyncio
import websockets
import json

async def test_ws():
    try:
        uri = 'ws://localhost:8000/api/v1/ws'
        async with websockets.connect(uri, close_timeout=1) as websocket:
            return True
    except:
        return False

result = asyncio.run(test_ws())
exit(0 if result else 1)
" 2>/dev/null; then
    echo -e "${GREEN}✓ PASSED${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}⚠ WebSocket not available (optional)${NC}"
fi

# 10. Performance test
echo -e "\n${YELLOW}10. Performance Tests${NC}"
echo -n "Testing API response time... "
RESPONSE_TIME=$(curl -o /dev/null -s -w '%{time_total}' -H "Authorization: Bearer $TOKEN" $API_URL/api/v1/nodes)
if (( $(echo "$RESPONSE_TIME < 1.0" | bc -l) )); then
    echo -e "${GREEN}✓ PASSED (${RESPONSE_TIME}s)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}⚠ SLOW (${RESPONSE_TIME}s)${NC}"
    ((TESTS_PASSED++))
fi

# Summary
echo -e "\n${BLUE}================================${NC}"
echo -e "${BLUE}Test Summary${NC}"
echo -e "${BLUE}================================${NC}"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}✓ All tests passed! Deployment successful.${NC}"
    
    # Show access information
    echo -e "\n${BLUE}Access Information:${NC}"
    echo -e "Web UI: ${GREEN}http://$(hostname -I | awk '{print $1}'):8000${NC}"
    echo -e "API Docs: ${GREEN}http://$(hostname -I | awk '{print $1}'):8000/api/docs${NC}"
    echo -e "Username: ${YELLOW}$DEFAULT_USER${NC}"
    echo -e "Password: ${YELLOW}$DEFAULT_PASS${NC}"
    echo -e "\n${YELLOW}⚠ Remember to change the default password!${NC}"
    
    exit 0
else
    echo -e "\n${RED}✗ Some tests failed. Please check the logs:${NC}"
    echo -e "  ${YELLOW}journalctl -u dns-proxy-controller -n 50${NC}"
    echo -e "  ${YELLOW}tail -f /opt/dns-proxy/logs/controller.log${NC}"
    exit 1
fi
