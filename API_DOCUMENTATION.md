# DNS-Loki API Documentation v2.0

## Overview
DNS-Loki provides a comprehensive REST API for managing DNS and proxy services across distributed nodes.

## Base URL
```
http://<server-ip>:8000/api/v1
```

## Authentication
All API endpoints (except `/auth/login`) require JWT authentication.

### Login
```http
POST /api/v1/auth/login
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin123
```

Response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

Use the token in subsequent requests:
```http
Authorization: Bearer <access_token>
```

## API Endpoints

### Authentication

#### Login
- **POST** `/api/v1/auth/login` - Authenticate and get access token
- **POST** `/api/v1/auth/refresh` - Refresh access token
- **POST** `/api/v1/auth/logout` - Logout and invalidate token

#### Users
- **GET** `/api/v1/auth/users` - List all users (admin only)
- **POST** `/api/v1/auth/users` - Create new user (admin only)
- **GET** `/api/v1/auth/users/{user_id}` - Get user details
- **PUT** `/api/v1/auth/users/{user_id}` - Update user
- **DELETE** `/api/v1/auth/users/{user_id}` - Delete user (admin only)
- **GET** `/api/v1/auth/me` - Get current user info
- **PUT** `/api/v1/auth/me/password` - Change password

### Nodes Management

#### List Nodes
```http
GET /api/v1/nodes
```

Response:
```json
[
  {
    "ip": "192.168.1.10",
    "name": "iran-server",
    "location": "Tehran",
    "roles": ["dns", "proxy"],
    "status": {
      "online": true,
      "agent_version": "2.0.0",
      "last_heartbeat": "2024-01-15T10:30:00Z",
      "services": {
        "agent": "running",
        "coredns": "running",
        "sniproxy": "running"
      }
    }
  }
]
```

#### Create Node
```http
POST /api/v1/nodes
Content-Type: application/json

{
  "ip": "192.168.1.20",
  "name": "new-node",
  "location": "Dubai",
  "ssh_user": "root",
  "ssh_password": "password",
  "ssh_port": 22,
  "roles": ["dns", "proxy"]
}
```

#### Get Node
```http
GET /api/v1/nodes/{ip}
```

#### Update Node
```http
PUT /api/v1/nodes/{ip}
Content-Type: application/json

{
  "name": "updated-name",
  "location": "New Location"
}
```

#### Delete Node
```http
DELETE /api/v1/nodes/{ip}
```

#### Node Actions
- **POST** `/api/v1/nodes/{ip}/restart` - Restart services on node
- **POST** `/api/v1/nodes/{ip}/sync` - Force sync with node
- **POST** `/api/v1/nodes/{ip}/heartbeat` - Record heartbeat
- **GET** `/api/v1/nodes/{ip}/logs` - Get node logs
- **GET** `/api/v1/nodes/{ip}/status` - Get detailed status

### Clients Management

#### List Clients
```http
GET /api/v1/clients
```

Response:
```json
[
  {
    "ip": "10.0.0.100",
    "name": "client-1",
    "type": "both",
    "active": true,
    "description": "Main office client",
    "created_at": "2024-01-15T10:00:00Z",
    "last_seen": "2024-01-15T12:00:00Z"
  }
]
```

#### Create Client
```http
POST /api/v1/clients
Content-Type: application/json

{
  "ip": "10.0.0.101",
  "name": "new-client",
  "type": "dns",
  "active": true,
  "description": "Branch office"
}
```

#### Update Client
```http
PUT /api/v1/clients/{ip}
Content-Type: application/json

{
  "active": false,
  "description": "Disabled temporarily"
}
```

#### Delete Client
```http
DELETE /api/v1/clients/{ip}
```

#### Bulk Operations
- **POST** `/api/v1/clients/bulk` - Create multiple clients
- **DELETE** `/api/v1/clients/bulk` - Delete multiple clients
- **PUT** `/api/v1/clients/bulk/activate` - Activate multiple clients
- **PUT** `/api/v1/clients/bulk/deactivate` - Deactivate multiple clients

### Configuration

#### Get Configuration
```http
GET /api/v1/config
```

Response:
```json
{
  "flags": {
    "enforce_dns_clients": true,
    "enable_monitoring": true,
    "debug_mode": false,
    "auto_sync": true,
    "sync_interval": 300
  },
  "dns": {
    "upstream_servers": ["8.8.8.8", "8.8.4.4"],
    "cache_size": 10000,
    "ttl": 300
  },
  "proxy": {
    "port": 443,
    "workers": 4,
    "timeout": 30
  }
}
```

#### Update Flags
```http
PUT /api/v1/config/flags
Content-Type: application/json

{
  "enforce_dns_clients": true,
  "debug_mode": false
}
```

#### Update DNS Config
```http
PUT /api/v1/config/dns
Content-Type: application/json

{
  "upstream_servers": ["1.1.1.1", "1.0.0.1"],
  "cache_size": 20000
}
```

#### Update Proxy Config
```http
PUT /api/v1/config/proxy
Content-Type: application/json

{
  "workers": 8,
  "timeout": 60
}
```

### Synchronization

#### Get Sync Status
```http
GET /api/v1/sync/status
```

Response:
```json
{
  "last_sync": "2024-01-15T12:00:00Z",
  "nodes_synced": 5,
  "nodes_failed": 0,
  "sync_in_progress": false,
  "next_sync": "2024-01-15T12:05:00Z"
}
```

#### Force Sync All
```http
POST /api/v1/sync/all
```

#### Sync Specific Node
```http
POST /api/v1/sync/node/{ip}
```

#### Get Sync History
```http
GET /api/v1/sync/history?limit=100
```

### Monitoring

#### Get System Status
```http
GET /api/v1/monitoring/status
```

Response:
```json
{
  "controller": {
    "status": "healthy",
    "uptime": 86400,
    "version": "2.0.0"
  },
  "nodes": {
    "total": 5,
    "online": 4,
    "offline": 1
  },
  "clients": {
    "total": 100,
    "active": 85,
    "inactive": 15
  },
  "services": {
    "dns": {
      "requests_total": 1000000,
      "requests_per_second": 100,
      "cache_hit_rate": 0.85
    },
    "proxy": {
      "connections_total": 50000,
      "active_connections": 150
    }
  }
}
```

#### Get Metrics
```http
GET /api/v1/monitoring/metrics
```

Returns Prometheus-compatible metrics.

#### Get Alerts
```http
GET /api/v1/monitoring/alerts
```

#### Health Check
```http
GET /api/v1/monitoring/health
```

Returns 200 OK if healthy, 503 if unhealthy.

## Error Responses

All errors follow this format:
```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {}
  }
}
```

Common error codes:
- `UNAUTHORIZED` - Invalid or missing authentication
- `FORBIDDEN` - Insufficient permissions
- `NOT_FOUND` - Resource not found
- `VALIDATION_ERROR` - Invalid input data
- `CONFLICT` - Resource already exists
- `INTERNAL_ERROR` - Server error

## Rate Limiting

API requests are rate-limited:
- Authenticated users: 1000 requests/minute
- Unauthenticated: 100 requests/minute

Rate limit headers:
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1642248000
```

## WebSocket Events

Connect to WebSocket for real-time updates:
```javascript
ws://server-ip:8000/api/v1/ws
```

Event types:
- `node.status` - Node status change
- `client.update` - Client added/removed
- `config.change` - Configuration updated
- `sync.progress` - Sync progress updates
- `alert.new` - New alert

## Examples

### Python
```python
import requests

# Login
response = requests.post(
    "http://server:8000/api/v1/auth/login",
    data={"username": "admin", "password": "admin123"}
)
token = response.json()["access_token"]

# Use API
headers = {"Authorization": f"Bearer {token}"}
nodes = requests.get(
    "http://server:8000/api/v1/nodes",
    headers=headers
).json()
```

### cURL
```bash
# Login
TOKEN=$(curl -X POST http://server:8000/api/v1/auth/login \
  -d "username=admin&password=admin123" \
  | jq -r .access_token)

# Get nodes
curl -H "Authorization: Bearer $TOKEN" \
  http://server:8000/api/v1/nodes
```

### JavaScript
```javascript
// Login
const response = await fetch('http://server:8000/api/v1/auth/login', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'username=admin&password=admin123'
});
const {access_token} = await response.json();

// Use API
const nodes = await fetch('http://server:8000/api/v1/nodes', {
  headers: {'Authorization': `Bearer ${access_token}`}
}).then(r => r.json());
```
