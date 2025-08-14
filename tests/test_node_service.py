"""
Tests for Node Service
"""

import pytest
from datetime import datetime, timedelta
from controller.services.node_service import NodeService
from controller.models.node import NodeCreate, NodeUpdate


@pytest.mark.asyncio
async def test_create_node():
    """Test node creation"""
    node_service = NodeService()
    
    node_data = NodeCreate(
        ip="192.168.1.100",
        name="test-node",
        location="US",
        ssh_user="root",
        ssh_password="password",
        ssh_port=22,
        roles=["dns", "proxy"]
    )
    
    node = await node_service.create_node(node_data)
    
    assert node.ip == "192.168.1.100"
    assert node.name == "test-node"
    assert node.location == "US"
    assert "dns" in node.roles
    assert "proxy" in node.roles


@pytest.mark.asyncio
async def test_get_node():
    """Test getting node by IP"""
    node_service = NodeService()
    
    # Create node
    node_data = NodeCreate(
        ip="192.168.1.101",
        name="get-test-node",
        location="EU"
    )
    await node_service.create_node(node_data)
    
    # Get node
    node = await node_service.get_node("192.168.1.101")
    assert node is not None
    assert node.ip == "192.168.1.101"
    assert node.name == "get-test-node"


@pytest.mark.asyncio
async def test_update_node():
    """Test node update"""
    node_service = NodeService()
    
    # Create node
    node_data = NodeCreate(
        ip="192.168.1.102",
        name="update-node",
        location="US"
    )
    node = await node_service.create_node(node_data)
    
    # Update node
    update_data = NodeUpdate(
        name="updated-node",
        location="EU"
    )
    updated = await node_service.update_node("192.168.1.102", update_data)
    
    assert updated.name == "updated-node"
    assert updated.location == "EU"


@pytest.mark.asyncio
async def test_delete_node():
    """Test node deletion"""
    node_service = NodeService()
    
    # Create node
    node_data = NodeCreate(
        ip="192.168.1.103",
        name="delete-node"
    )
    await node_service.create_node(node_data)
    
    # Delete node
    result = await node_service.delete_node("192.168.1.103")
    assert result is True
    
    # Node should not exist
    node = await node_service.get_node("192.168.1.103")
    assert node is None


@pytest.mark.asyncio
async def test_record_heartbeat():
    """Test recording node heartbeat"""
    node_service = NodeService()
    
    # Create node
    node_data = NodeCreate(
        ip="192.168.1.104",
        name="heartbeat-node"
    )
    node = await node_service.create_node(node_data)
    
    # Record heartbeat
    result = await node_service.record_heartbeat("192.168.1.104", "1.0.0")
    assert result is True
    
    # Check node status
    node = await node_service.get_node("192.168.1.104")
    assert node.status.online is True
    assert node.status.agent_version == "1.0.0"
    assert node.status.last_heartbeat is not None


@pytest.mark.asyncio
async def test_get_all_nodes():
    """Test getting all nodes"""
    node_service = NodeService()
    
    # Create multiple nodes
    for i in range(3):
        node_data = NodeCreate(
            ip=f"192.168.1.{110 + i}",
            name=f"test-node-{i}"
        )
        await node_service.create_node(node_data)
    
    # Get all nodes
    nodes = await node_service.get_all_nodes()
    assert len(nodes) >= 3


@pytest.mark.asyncio
async def test_get_online_nodes():
    """Test getting online nodes"""
    node_service = NodeService()
    
    # Create nodes
    for i in range(2):
        node_data = NodeCreate(
            ip=f"192.168.1.{120 + i}",
            name=f"online-node-{i}"
        )
        node = await node_service.create_node(node_data)
        # Record heartbeat for first node only
        if i == 0:
            await node_service.record_heartbeat(node.ip, "1.0.0")
    
    # Get online nodes
    online_nodes = await node_service.get_online_nodes()
    online_ips = [n.ip for n in online_nodes]
    assert "192.168.1.120" in online_ips
