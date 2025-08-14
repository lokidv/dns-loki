"""
Node data models for DNS-Loki Controller
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic.v1 import BaseModel, Field, validator, IPvAnyAddress
from enum import Enum


class NodeRole(str, Enum):
    """Node roles in the cluster"""
    DNS = "dns"
    PROXY = "proxy"
    BOTH = "both"


class ServiceStatus(str, Enum):
    """Service status"""
    RUNNING = "running"
    STOPPED = "stopped"
    UNKNOWN = "unknown"
    ERROR = "error"


class NodeStatus(BaseModel):
    """Node status information"""
    online: bool = False
    last_heartbeat: Optional[datetime] = None
    agent_version: Optional[str] = None
    services: Dict[str, ServiceStatus] = Field(default_factory=dict)
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    uptime: Optional[int] = None  # seconds
    
    @validator('last_heartbeat', pre=True)
    def parse_datetime(cls, v):
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace('Z', '+00:00'))
        return v
    
    @property
    def is_healthy(self) -> bool:
        """Check if node is healthy"""
        if not self.online:
            return False
        if self.last_heartbeat:
            # Consider unhealthy if no heartbeat for 3 minutes
            time_diff = (datetime.utcnow() - self.last_heartbeat).total_seconds()
            return time_diff < 180
        return False


class Node(BaseModel):
    """Node model"""
    ip: IPvAnyAddress
    name: str
    role: NodeRole = NodeRole.BOTH
    location: Optional[str] = None
    datacenter: Optional[str] = None
    provider: Optional[str] = None
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_user: str = "root"
    ssh_password: Optional[str] = None
    ssh_key: Optional[str] = None
    status: NodeStatus = Field(default_factory=NodeStatus)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            IPvAnyAddress: str
        }
    
    @validator('ip')
    def validate_ip(cls, v):
        """Ensure IP is stored as string"""
        return str(v)
    
    def dict(self, **kwargs):
        """Override dict to ensure IP is string"""
        d = super().dict(**kwargs)
        if 'ip' in d:
            d['ip'] = str(d['ip'])
        return d


class NodeCreate(BaseModel):
    """Model for creating a node"""
    ip: IPvAnyAddress
    name: str
    role: NodeRole = NodeRole.BOTH
    location: Optional[str] = None
    datacenter: Optional[str] = None
    provider: Optional[str] = None
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_user: str = "root"
    ssh_password: Optional[str] = None
    ssh_key: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('ip')
    def validate_ip(cls, v):
        return str(v)


class NodeUpdate(BaseModel):
    """Model for updating a node"""
    name: Optional[str] = None
    role: Optional[NodeRole] = None
    location: Optional[str] = None
    datacenter: Optional[str] = None
    provider: Optional[str] = None
    ssh_port: Optional[int] = Field(None, ge=1, le=65535)
    ssh_user: Optional[str] = None
    ssh_password: Optional[str] = None
    ssh_key: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class NodeCommand(BaseModel):
    """Model for node command execution"""
    command: str
    timeout: int = Field(default=30, ge=1, le=300)
    sudo: bool = False


class NodeCommandResult(BaseModel):
    """Result of node command execution"""
    success: bool
    output: str
    error: Optional[str] = None
    exit_code: int
    duration: float  # seconds


class NodeServiceAction(BaseModel):
    """Model for service actions on node"""
    service: str = Field(..., regex="^(agent|coredns|sniproxy)$")
    action: str = Field(..., regex="^(start|stop|restart|status)$")


class NodeBulkAction(BaseModel):
    """Model for bulk actions on nodes"""
    node_ips: List[IPvAnyAddress]
    action: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
