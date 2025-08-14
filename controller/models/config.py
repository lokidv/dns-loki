"""
Configuration data models for DNS-Loki Controller
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field, validator, HttpUrl


class Flags(BaseModel):
    """System flags/configuration"""
    enforce_dns_clients: bool = True
    enforce_proxy_clients: bool = False
    git_repo: Optional[HttpUrl] = None
    git_branch: str = "main"
    auto_update: bool = True
    update_interval: int = Field(default=60, ge=10, le=3600)  # seconds
    
    @validator('git_repo', pre=True)
    def validate_git_repo(cls, v):
        if v and not str(v).endswith('.git'):
            return f"{v}.git" if not str(v).endswith('/') else f"{v[:-1]}.git"
        return v


class Config(BaseModel):
    """System configuration"""
    flags: Flags = Field(default_factory=Flags)
    dns_settings: Dict[str, Any] = Field(default_factory=dict)
    proxy_settings: Dict[str, Any] = Field(default_factory=dict)
    network_settings: Dict[str, Any] = Field(default_factory=dict)
    monitoring_settings: Dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ConfigUpdate(BaseModel):
    """Model for updating configuration"""
    flags: Optional[Flags] = None
    dns_settings: Optional[Dict[str, Any]] = None
    proxy_settings: Optional[Dict[str, Any]] = None
    network_settings: Optional[Dict[str, Any]] = None
    monitoring_settings: Optional[Dict[str, Any]] = None


class DNSConfig(BaseModel):
    """DNS specific configuration"""
    upstream_servers: List[str] = Field(
        default=["8.8.8.8", "8.8.4.4"],
        min_items=1
    )
    cache_size: int = Field(default=10000, ge=100, le=100000)
    cache_ttl: int = Field(default=300, ge=10, le=86400)  # seconds
    blocked_domains: List[str] = Field(default_factory=list)
    allowed_domains: List[str] = Field(default_factory=list)
    custom_records: Dict[str, str] = Field(default_factory=dict)
    enable_dnssec: bool = False
    enable_logging: bool = True
    log_queries: bool = False


class ProxyConfig(BaseModel):
    """Proxy specific configuration"""
    listen_port: int = Field(default=443, ge=1, le=65535)
    upstream_timeout: int = Field(default=30, ge=5, le=300)  # seconds
    max_connections: int = Field(default=1000, ge=10, le=10000)
    buffer_size: int = Field(default=4096, ge=1024, le=65536)
    allowed_sni: List[str] = Field(default_factory=list)
    blocked_sni: List[str] = Field(default_factory=list)
    enable_tls_verification: bool = True
    enable_logging: bool = True


class NetworkConfig(BaseModel):
    """Network configuration"""
    interface: str = "eth0"
    mtu: int = Field(default=1500, ge=576, le=9000)
    enable_ipv6: bool = True
    nat_enabled: bool = True
    firewall_rules: List[Dict[str, Any]] = Field(default_factory=list)


class MonitoringConfig(BaseModel):
    """Monitoring configuration"""
    enable_metrics: bool = True
    metrics_port: int = Field(default=9090, ge=1, le=65535)
    enable_health_check: bool = True
    health_check_port: int = Field(default=8081, ge=1, le=65535)
    alert_endpoints: List[HttpUrl] = Field(default_factory=list)
    alert_thresholds: Dict[str, float] = Field(
        default_factory=lambda: {
            "cpu_usage": 80.0,
            "memory_usage": 80.0,
            "disk_usage": 90.0
        }
    )
