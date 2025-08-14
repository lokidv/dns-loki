"""
Monitoring models for DNS-Loki Controller
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic.v1 import BaseModel, Field
from enum import Enum


class ServiceStatus(str, Enum):
    """Service status enumeration"""
    RUNNING = "running"
    STOPPED = "stopped"
    UNKNOWN = "unknown"
    ERROR = "error"


class AlertSeverity(str, Enum):
    """Alert severity levels"""
    INFO = "info" 
    WARNING = "warning"
    CRITICAL = "critical"


class SystemMetrics(BaseModel):
    """System metrics model"""
    timestamp: datetime
    cpu: Dict[str, Any] = Field(default_factory=dict)
    memory: Dict[str, Any] = Field(default_factory=dict)
    disk: Dict[str, Any] = Field(default_factory=dict)
    network: Dict[str, Any] = Field(default_factory=dict)
    processes: int = 0
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class HealthCheck(BaseModel):
    """Health check model"""
    status: str
    timestamp: datetime
    service: str = "dns-loki-controller"
    version: str = "2.0.0"
    monitoring_active: bool = False
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class PerformanceMetrics(BaseModel):
    """Performance metrics model"""
    period: str
    data_points: int = 0
    averages: Dict[str, float] = Field(default_factory=dict)
    latest: Optional[SystemMetrics] = None


class Alert(BaseModel):
    """Alert model"""
    id: str
    type: str
    severity: AlertSeverity
    message: str
    timestamp: datetime
    active: bool = True
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved: bool = False
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolution: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class AlertCreate(BaseModel):
    """Model for creating alerts"""
    type: str
    severity: AlertSeverity
    message: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class LogEntry(BaseModel):
    """Log entry model"""
    timestamp: datetime
    level: str
    source: str
    message: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
