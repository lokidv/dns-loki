"""
Client data models for DNS-Loki Controller
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field, validator, IPvAnyAddress


class ClientType(str):
    """Client types"""
    DNS = "dns"
    PROXY = "proxy"
    BOTH = "both"


class Client(BaseModel):
    """Client model"""
    ip: IPvAnyAddress
    name: Optional[str] = None
    type: str = ClientType.BOTH
    allowed_domains: List[str] = Field(default_factory=list)
    blocked_domains: List[str] = Field(default_factory=list)
    bandwidth_limit: Optional[int] = None  # bytes per second
    active: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_seen: Optional[datetime] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            IPvAnyAddress: str
        }
    
    @validator('ip')
    def validate_ip(cls, v):
        """Ensure IP is stored as string"""
        return str(v)
    
    @validator('type')
    def validate_type(cls, v):
        """Validate client type"""
        valid_types = [ClientType.DNS, ClientType.PROXY, ClientType.BOTH]
        if v not in valid_types:
            raise ValueError(f"Invalid client type. Must be one of {valid_types}")
        return v
    
    def dict(self, **kwargs):
        """Override dict to ensure IP is string"""
        d = super().dict(**kwargs)
        if 'ip' in d:
            d['ip'] = str(d['ip'])
        return d


class ClientCreate(BaseModel):
    """Model for creating a client"""
    ip: IPvAnyAddress
    name: Optional[str] = None
    type: str = ClientType.BOTH
    allowed_domains: List[str] = Field(default_factory=list)
    blocked_domains: List[str] = Field(default_factory=list)
    bandwidth_limit: Optional[int] = None
    active: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('ip')
    def validate_ip(cls, v):
        return str(v)
    
    @validator('type')
    def validate_type(cls, v):
        valid_types = [ClientType.DNS, ClientType.PROXY, ClientType.BOTH]
        if v not in valid_types:
            raise ValueError(f"Invalid client type. Must be one of {valid_types}")
        return v


class ClientUpdate(BaseModel):
    """Model for updating a client"""
    name: Optional[str] = None
    type: Optional[str] = None
    allowed_domains: Optional[List[str]] = None
    blocked_domains: Optional[List[str]] = None
    bandwidth_limit: Optional[int] = None
    active: Optional[bool] = None
    metadata: Optional[Dict[str, Any]] = None
    
    @validator('type')
    def validate_type(cls, v):
        if v is not None:
            valid_types = [ClientType.DNS, ClientType.PROXY, ClientType.BOTH]
            if v not in valid_types:
                raise ValueError(f"Invalid client type. Must be one of {valid_types}")
        return v


class ClientStats(BaseModel):
    """Client statistics"""
    ip: IPvAnyAddress
    total_requests: int = 0
    blocked_requests: int = 0
    bandwidth_used: int = 0  # bytes
    last_request: Optional[datetime] = None
    top_domains: List[Dict[str, Any]] = Field(default_factory=list)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            IPvAnyAddress: str
        }


class ClientBulkAction(BaseModel):
    """Model for bulk actions on clients"""
    client_ips: List[IPvAnyAddress]
    action: str = Field(..., regex="^(activate|deactivate|delete)$")
    parameters: Dict[str, Any] = Field(default_factory=dict)
