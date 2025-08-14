"""
Synchronization models for DNS-Loki Controller
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic.v1 import BaseModel, Field
from enum import Enum


class SyncStatus(str, Enum):
    """Sync status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SyncResult(BaseModel):
    """Result of a sync operation"""
    node_ip: str
    status: SyncStatus
    message: Optional[str] = None
    version: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration: Optional[float] = None  # seconds
    error: Optional[str] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class SyncConfig(BaseModel):
    """Sync configuration"""
    auto_sync: bool = Field(default=True, description="Enable automatic sync")
    sync_interval: int = Field(default=60, ge=30, le=3600, description="Sync interval in seconds")
    sync_timeout: int = Field(default=30, ge=5, le=300, description="Sync timeout in seconds")
    max_concurrent: int = Field(default=5, ge=1, le=20, description="Maximum concurrent syncs")
    retry_attempts: int = Field(default=3, ge=0, le=10, description="Number of retry attempts")
    retry_delay: int = Field(default=5, ge=1, le=60, description="Delay between retries in seconds")


class SyncStatusResponse(BaseModel):
    """Overall sync status response"""
    is_syncing: bool
    last_sync: Optional[datetime] = None
    next_sync: Optional[datetime] = None
    sync_version: Optional[str] = None
    total_nodes: int = 0
    synced_nodes: int = 0
    failed_nodes: int = 0
    pending_changes: bool = False
    config: SyncConfig
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class BulkSyncRequest(BaseModel):
    """Request for bulk sync operation"""
    node_ips: Optional[List[str]] = None  # If None, sync all nodes
    force: bool = Field(default=False, description="Force sync even if already synced")
    timeout: int = Field(default=30, ge=5, le=300, description="Timeout per node")


class BulkSyncResponse(BaseModel):
    """Response for bulk sync operation"""
    sync_id: str
    total_nodes: int
    results: List[SyncResult]
    started_at: datetime
    completed_at: Optional[datetime] = None
    success_count: int = 0
    failed_count: int = 0
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
