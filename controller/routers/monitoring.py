"""
Monitoring API router for DNS-Loki Controller
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import JSONResponse

from ..services.monitoring_service import MonitoringService
from ..services.auth_service import AuthService
from ..models.monitoring import (
    SystemMetrics, ServiceStatus, Alert, AlertCreate,
    HealthCheck, PerformanceMetrics, LogEntry
)
from ..models.auth import User
from ..core.dependencies import get_current_user, require_permission


router = APIRouter(prefix="/api/v1/monitoring", tags=["monitoring"])
monitoring_service = MonitoringService()
auth_service = AuthService()


@router.get("/health")
async def health_check():
    """Basic health check endpoint"""
    try:
        health = await monitoring_service.health_check()
        return health
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/status", response_model=Dict[str, ServiceStatus])
async def get_system_status(
    current_user: User = Depends(get_current_user)
):
    """Get overall system status"""
    try:
        status = await monitoring_service.get_system_status()
        return status
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/metrics", response_model=SystemMetrics)
async def get_system_metrics(
    current_user: User = Depends(get_current_user)
):
    """Get system metrics"""
    try:
        metrics = await monitoring_service.get_system_metrics()
        return metrics
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/nodes/{ip}/metrics")
async def get_node_metrics(
    ip: str,
    period: str = Query("1h", description="Time period: 1h, 6h, 24h, 7d"),
    current_user: User = Depends(get_current_user)
):
    """Get metrics for specific node"""
    try:
        metrics = await monitoring_service.get_node_metrics(ip, period)
        return metrics
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/performance", response_model=PerformanceMetrics)
async def get_performance_metrics(
    period: str = Query("1h", description="Time period: 1h, 6h, 24h, 7d"),
    current_user: User = Depends(get_current_user)
):
    """Get performance metrics"""
    try:
        metrics = await monitoring_service.get_performance_metrics(period)
        return metrics
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/alerts", response_model=List[Alert])
async def get_alerts(
    active_only: bool = Query(True, description="Show only active alerts"),
    severity: Optional[str] = Query(None, description="Filter by severity: critical, warning, info"),
    current_user: User = Depends(get_current_user)
):
    """Get system alerts"""
    try:
        alerts = await monitoring_service.get_alerts(active_only, severity)
        return alerts
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/alerts", response_model=Alert)
async def create_alert(
    alert_data: AlertCreate,
    current_user: User = Depends(require_permission("manage_monitoring"))
):
    """Create new alert"""
    try:
        alert = await monitoring_service.create_alert(alert_data)
        return alert
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    current_user: User = Depends(require_permission("manage_monitoring"))
):
    """Acknowledge alert"""
    try:
        result = await monitoring_service.acknowledge_alert(alert_id, current_user.username)
        return {"success": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    resolution: str = Query(..., description="Resolution description"),
    current_user: User = Depends(require_permission("manage_monitoring"))
):
    """Resolve alert"""
    try:
        result = await monitoring_service.resolve_alert(alert_id, resolution, current_user.username)
        return {"success": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/logs", response_model=List[LogEntry])
async def get_logs(
    level: Optional[str] = Query(None, description="Log level: debug, info, warning, error, critical"),
    source: Optional[str] = Query(None, description="Log source"),
    limit: int = Query(100, description="Number of logs to return"),
    offset: int = Query(0, description="Offset for pagination"),
    current_user: User = Depends(get_current_user)
):
    """Get system logs"""
    try:
        logs = await monitoring_service.get_logs(level, source, limit, offset)
        return logs
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/logs/search")
async def search_logs(
    query: str = Query(..., description="Search query"),
    start_time: Optional[datetime] = Query(None, description="Start time"),
    end_time: Optional[datetime] = Query(None, description="End time"),
    limit: int = Query(100, description="Number of results"),
    current_user: User = Depends(get_current_user)
):
    """Search logs"""
    try:
        logs = await monitoring_service.search_logs(query, start_time, end_time, limit)
        return logs
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/statistics")
async def get_statistics(
    period: str = Query("24h", description="Time period: 1h, 6h, 24h, 7d, 30d"),
    current_user: User = Depends(get_current_user)
):
    """Get system statistics"""
    try:
        stats = await monitoring_service.get_statistics(period)
        return stats
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/dns/queries")
async def get_dns_query_stats(
    period: str = Query("1h", description="Time period"),
    current_user: User = Depends(get_current_user)
):
    """Get DNS query statistics"""
    try:
        stats = await monitoring_service.get_dns_query_stats(period)
        return stats
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/proxy/connections")
async def get_proxy_connection_stats(
    period: str = Query("1h", description="Time period"),
    current_user: User = Depends(get_current_user)
):
    """Get proxy connection statistics"""
    try:
        stats = await monitoring_service.get_proxy_connection_stats(period)
        return stats
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/test/notification")
async def test_notification(
    type: str = Query(..., description="Notification type: email, webhook, telegram"),
    current_user: User = Depends(require_permission("manage_monitoring"))
):
    """Test notification channel"""
    try:
        result = await monitoring_service.test_notification(type)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
