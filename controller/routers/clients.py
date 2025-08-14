"""
Clients API router for DNS-Loki Controller
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import JSONResponse

from ..services.client_service import ClientService
from ..services.auth_service import AuthService
from ..models.client import Client, ClientCreate, ClientUpdate, ClientStats
from ..models.auth import User
from ..core.dependencies import get_current_user, require_permission


router = APIRouter(prefix="/api/v1/clients", tags=["clients"])
client_service = ClientService()
auth_service = AuthService()


@router.get("/", response_model=List[Client])
async def get_clients(
    active_only: bool = Query(False, description="Filter active clients only"),
    client_type: Optional[str] = Query(None, description="Filter by type: dns, proxy, both"),
    current_user: User = Depends(get_current_user)
):
    """Get all clients"""
    clients = await client_service.get_all_clients()
    
    if active_only:
        clients = [c for c in clients if c.active]
    
    if client_type:
        clients = [c for c in clients if c.type == client_type]
    
    return clients


@router.get("/{ip}", response_model=Client)
async def get_client(
    ip: str,
    current_user: User = Depends(get_current_user)
):
    """Get specific client"""
    try:
        client = await client_service.get_client(ip)
        return client
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/", response_model=Client)
async def create_client(
    client_data: ClientCreate,
    current_user: User = Depends(require_permission("manage_clients"))
):
    """Create new client"""
    try:
        client = await client_service.create_client(client_data)
        return client
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/{ip}", response_model=Client)
async def update_client(
    ip: str,
    update_data: ClientUpdate,
    current_user: User = Depends(require_permission("manage_clients"))
):
    """Update client"""
    try:
        client = await client_service.update_client(ip, update_data)
        return client
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{ip}")
async def delete_client(
    ip: str,
    current_user: User = Depends(require_permission("manage_clients"))
):
    """Delete client"""
    try:
        result = await client_service.delete_client(ip)
        return {"success": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/bulk/create")
async def bulk_create_clients(
    client_ips: List[str],
    current_user: User = Depends(require_permission("manage_clients"))
):
    """Create multiple clients"""
    try:
        clients = await client_service.bulk_create_clients(client_ips)
        return {"created": len(clients), "clients": clients}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/bulk/delete")
async def bulk_delete_clients(
    client_ips: List[str],
    current_user: User = Depends(require_permission("manage_clients"))
):
    """Delete multiple clients"""
    try:
        results = await client_service.bulk_delete_clients(client_ips)
        return results
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{ip}/activate")
async def activate_client(
    ip: str,
    current_user: User = Depends(require_permission("manage_clients"))
):
    """Activate client"""
    try:
        client = await client_service.activate_client(ip)
        return client
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{ip}/deactivate")
async def deactivate_client(
    ip: str,
    current_user: User = Depends(require_permission("manage_clients"))
):
    """Deactivate client"""
    try:
        client = await client_service.deactivate_client(ip)
        return client
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{ip}/stats", response_model=ClientStats)
async def get_client_stats(
    ip: str,
    current_user: User = Depends(get_current_user)
):
    """Get client statistics"""
    try:
        stats = await client_service.get_client_stats(ip)
        return stats
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/search/")
async def search_clients(
    query: Optional[str] = Query(None, description="Search query"),
    active_only: bool = Query(False, description="Filter active only"),
    client_type: Optional[str] = Query(None, description="Filter by type"),
    current_user: User = Depends(get_current_user)
):
    """Search clients"""
    try:
        clients = await client_service.search_clients(query, active_only, client_type)
        return clients
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/export/")
async def export_clients(
    current_user: User = Depends(require_permission("manage_clients"))
):
    """Export all clients data"""
    try:
        data = await client_service.export_clients()
        return data
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/import/")
async def import_clients(
    data: Dict[str, Any],
    current_user: User = Depends(require_permission("manage_clients"))
):
    """Import clients data"""
    try:
        result = await client_service.import_clients(data)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
