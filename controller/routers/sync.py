"""
Synchronization API router for DNS-Loki Controller
"""

from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import JSONResponse

from ..services.sync_service import SyncService
from ..services.auth_service import AuthService
from ..models.sync import SyncStatus, SyncResult, SyncConfig
from ..models.auth import User
from ..core.dependencies import get_current_user, require_permission


router = APIRouter(prefix="/api/v1/sync", tags=["sync"])
sync_service = SyncService()
auth_service = AuthService()


@router.get("/status", response_model=SyncStatus)
async def get_sync_status(
    current_user: User = Depends(get_current_user)
):
    """Get current sync status"""
    try:
        status = await sync_service.get_sync_status()
        return status
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/trigger")
async def trigger_sync(
    force: bool = Query(False, description="Force sync even if not needed"),
    current_user: User = Depends(require_permission("manage_sync"))
):
    """Trigger synchronization to all nodes"""
    try:
        result = await sync_service.trigger_sync(force=force)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/nodes/{ip}/sync")
async def sync_node(
    ip: str,
    force: bool = Query(False, description="Force sync even if not needed"),
    current_user: User = Depends(require_permission("manage_sync"))
):
    """Sync specific node"""
    try:
        result = await sync_service.sync_node(ip, force=force)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/clients/sync")
async def sync_clients(
    current_user: User = Depends(require_permission("manage_sync"))
):
    """Sync client allowlists to all nodes"""
    try:
        result = await sync_service.sync_clients()
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/config/sync")
async def sync_config(
    current_user: User = Depends(require_permission("manage_sync"))
):
    """Sync configuration to all nodes"""
    try:
        result = await sync_service.sync_config()
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/agents/update")
async def update_agents(
    version: str = Query(..., description="Target agent version"),
    node_ips: List[str] = Query(None, description="Specific nodes to update"),
    current_user: User = Depends(require_permission("manage_sync"))
):
    """Update agents to specific version"""
    try:
        result = await sync_service.update_agents(version, node_ips)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/history")
async def get_sync_history(
    limit: int = Query(100, description="Number of records to return"),
    current_user: User = Depends(get_current_user)
):
    """Get synchronization history"""
    try:
        history = await sync_service.get_sync_history(limit)
        return history
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/config", response_model=SyncConfig)
async def get_sync_config(
    current_user: User = Depends(get_current_user)
):
    """Get sync configuration"""
    try:
        config = await sync_service.get_sync_config()
        return config
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/config", response_model=SyncConfig)
async def update_sync_config(
    config: SyncConfig,
    current_user: User = Depends(require_permission("manage_sync"))
):
    """Update sync configuration"""
    try:
        updated_config = await sync_service.update_sync_config(config)
        return updated_config
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/reset")
async def reset_sync(
    current_user: User = Depends(require_permission("manage_sync"))
):
    """Reset sync state and force full sync"""
    try:
        result = await sync_service.reset_sync()
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/queue")
async def get_sync_queue(
    current_user: User = Depends(get_current_user)
):
    """Get pending sync operations"""
    try:
        queue = await sync_service.get_sync_queue()
        return queue
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/queue/{operation_id}")
async def cancel_sync_operation(
    operation_id: str,
    current_user: User = Depends(require_permission("manage_sync"))
):
    """Cancel pending sync operation"""
    try:
        result = await sync_service.cancel_sync_operation(operation_id)
        return {"success": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/validate")
async def validate_sync(
    current_user: User = Depends(get_current_user)
):
    """Validate sync state across all nodes"""
    try:
        result = await sync_service.validate_sync()
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
