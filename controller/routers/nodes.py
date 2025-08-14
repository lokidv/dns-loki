"""
Nodes API router for DNS-Loki Controller
"""

from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import JSONResponse

from ..services.node_service import NodeService
from ..services.auth_service import AuthService
from ..models.node import Node, NodeCreate, NodeUpdate, NodeStatus
from ..models.auth import User
from ..core.dependencies import get_current_user, require_permission


router = APIRouter(prefix="/api/v1/nodes", tags=["nodes"])
node_service = NodeService()
auth_service = AuthService()


@router.get("/", response_model=List[Node])
async def get_nodes(
    online_only: bool = Query(False, description="Filter online nodes only"),
    current_user: User = Depends(get_current_user)
):
    """Get all nodes"""
    nodes = await node_service.get_all_nodes()
    
    if online_only:
        nodes = [n for n in nodes if n.status.online]
    
    return nodes


@router.get("/{ip}", response_model=Node)
async def get_node(
    ip: str,
    current_user: User = Depends(get_current_user)
):
    """Get specific node"""
    try:
        node = await node_service.get_node(ip)
        return node
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/", response_model=Node)
async def create_node(
    node_data: NodeCreate,
    current_user: User = Depends(require_permission("manage_nodes"))
):
    """Create new node"""
    try:
        node = await node_service.create_node(node_data)
        return node
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/{ip}", response_model=Node)
async def update_node(
    ip: str,
    update_data: NodeUpdate,
    current_user: User = Depends(require_permission("manage_nodes"))
):
    """Update node"""
    try:
        node = await node_service.update_node(ip, update_data)
        return node
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{ip}")
async def delete_node(
    ip: str,
    current_user: User = Depends(require_permission("manage_nodes"))
):
    """Delete node"""
    try:
        result = await node_service.delete_node(ip)
        return {"success": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{ip}/heartbeat")
async def record_heartbeat(
    ip: str,
    agent_version: str = Query(None, description="Agent version")
):
    """Record node heartbeat (called by agents)"""
    try:
        result = await node_service.record_heartbeat(ip, agent_version)
        return {"success": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{ip}/restart")
async def restart_node_service(
    ip: str,
    service: str = Query(..., description="Service to restart: agent, coredns, sniproxy"),
    current_user: User = Depends(require_permission("manage_nodes"))
):
    """Restart service on node"""
    try:
        result = await node_service.restart_service(ip, service)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{ip}/execute")
async def execute_command(
    ip: str,
    command: str = Query(..., description="Command to execute"),
    timeout: int = Query(30, description="Command timeout in seconds"),
    current_user: User = Depends(require_permission("manage_nodes"))
):
    """Execute command on node"""
    try:
        result = await node_service.execute_command(ip, command, timeout)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{ip}/metrics")
async def get_node_metrics(
    ip: str,
    current_user: User = Depends(get_current_user)
):
    """Get node system metrics"""
    try:
        metrics = await node_service.get_node_metrics(ip)
        return metrics
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/bulk/restart")
async def bulk_restart_services(
    node_ips: List[str],
    services: List[str],
    current_user: User = Depends(require_permission("manage_nodes"))
):
    """Restart services on multiple nodes"""
    try:
        results = await node_service.bulk_restart_services(node_ips, services)
        return results
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{ip}/test-connection")
async def test_node_connection(
    ip: str,
    current_user: User = Depends(require_permission("manage_nodes"))
):
    """Test SSH connection to node"""
    try:
        node = await node_service.get_node(ip)
        result = await node_service.test_node_connection(node)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
