"""
Node management service for DNS-Loki Controller
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import asyncio

from ..core.database import state_manager, cache_manager
from ..core.logging import get_logger
from ..core.exceptions import NodeNotFoundError, NodeConnectionError, ValidationError
from ..models.node import Node, NodeCreate, NodeUpdate, NodeStatus, ServiceStatus
from .ssh_service import SSHService


logger = get_logger(__name__)


class NodeService:
    """Service for managing nodes"""
    
    def __init__(self):
        self.ssh_service = SSHService()
        self.heartbeat_timeout = 180  # seconds
    
    async def get_all_nodes(self) -> List[Node]:
        """Get all nodes"""
        nodes_data = await state_manager.get('nodes', {})
        nodes = []
        
        for ip, data in nodes_data.items():
            node = Node(**data)
            # Update online status based on heartbeat
            node.status.online = self._is_node_online(node.status.last_heartbeat)
            nodes.append(node)
        
        return nodes
    
    async def get_node(self, ip: str) -> Node:
        """Get a specific node"""
        nodes = await state_manager.get('nodes', {})
        
        if ip not in nodes:
            raise NodeNotFoundError(f"Node {ip} not found")
        
        node = Node(**nodes[ip])
        node.status.online = self._is_node_online(node.status.last_heartbeat)
        return node
    
    async def create_node(self, node_data: NodeCreate) -> Node:
        """Create a new node"""
        nodes = await state_manager.get('nodes', {})
        ip = str(node_data.ip)
        
        if ip in nodes:
            raise ValidationError(f"Node {ip} already exists")
        
        # Create node instance
        node = Node(
            **node_data.dict(),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        # Test SSH connection if credentials provided
        if node.ssh_password or node.ssh_key:
            try:
                await self.test_node_connection(node)
                node.status.online = True
            except Exception as e:
                logger.warning(f"Failed to connect to new node {ip}: {e}")
                node.status.online = False
        
        # Save to state
        nodes[ip] = node.dict()
        await state_manager.set('nodes', nodes)
        
        # Update stats
        await self._update_stats()
        
        logger.info(f"Created node {ip}")
        return node
    
    async def update_node(self, ip: str, update_data: NodeUpdate) -> Node:
        """Update a node"""
        nodes = await state_manager.get('nodes', {})
        
        if ip not in nodes:
            raise NodeNotFoundError(f"Node {ip} not found")
        
        # Update node data
        node_dict = nodes[ip]
        update_dict = update_data.dict(exclude_unset=True)
        
        for key, value in update_dict.items():
            if value is not None:
                node_dict[key] = value
        
        node_dict['updated_at'] = datetime.utcnow().isoformat()
        
        # Save to state
        nodes[ip] = node_dict
        await state_manager.set('nodes', nodes)
        
        logger.info(f"Updated node {ip}")
        return Node(**node_dict)
    
    async def delete_node(self, ip: str) -> bool:
        """Delete a node"""
        nodes = await state_manager.get('nodes', {})
        
        if ip not in nodes:
            raise NodeNotFoundError(f"Node {ip} not found")
        
        del nodes[ip]
        await state_manager.set('nodes', nodes)
        
        # Update stats
        await self._update_stats()
        
        # Clear cache
        await cache_manager.delete(f"node:{ip}")
        
        logger.info(f"Deleted node {ip}")
        return True
    
    async def update_node_status(self, ip: str, status: NodeStatus) -> Node:
        """Update node status"""
        nodes = await state_manager.get('nodes', {})
        
        if ip not in nodes:
            raise NodeNotFoundError(f"Node {ip} not found")
        
        nodes[ip]['status'] = status.dict()
        nodes[ip]['updated_at'] = datetime.utcnow().isoformat()
        
        await state_manager.set('nodes', nodes)
        
        # Cache status for quick access
        await cache_manager.set(f"node_status:{ip}", status.dict(), ttl=60)
        
        return Node(**nodes[ip])
    
    async def record_heartbeat(self, ip: str, agent_version: Optional[str] = None) -> bool:
        """Record node heartbeat"""
        nodes = await state_manager.get('nodes', {})
        
        if ip not in nodes:
            # Auto-register new node
            logger.info(f"Auto-registering new node {ip}")
            node_data = NodeCreate(ip=ip, name=f"node-{ip}")
            await self.create_node(node_data)
            nodes = await state_manager.get('nodes', {})
        
        # Update heartbeat
        nodes[ip]['status']['last_heartbeat'] = datetime.utcnow().isoformat()
        nodes[ip]['status']['online'] = True
        
        if agent_version:
            nodes[ip]['status']['agent_version'] = agent_version
        
        await state_manager.set('nodes', nodes)
        
        # Update active nodes count
        await self._update_active_nodes_count()
        
        return True
    
    async def test_node_connection(self, node: Node) -> Dict[str, Any]:
        """Test SSH connection to node"""
        try:
            result = await self.ssh_service.test_connection(
                host=str(node.ip),
                port=node.ssh_port,
                username=node.ssh_user,
                password=node.ssh_password,
                key=node.ssh_key
            )
            
            if result['success']:
                # Update node status
                node.status.online = True
                await self.update_node_status(str(node.ip), node.status)
            
            return result
        except Exception as e:
            logger.error(f"Failed to test connection to {node.ip}: {e}")
            raise NodeConnectionError(f"Failed to connect to {node.ip}: {e}")
    
    async def execute_command(
        self,
        ip: str,
        command: str,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """Execute command on node"""
        node = await self.get_node(ip)
        
        if not node.ssh_password and not node.ssh_key:
            raise ValidationError(f"No SSH credentials for node {ip}")
        
        try:
            result = await self.ssh_service.execute_command(
                host=str(node.ip),
                port=node.ssh_port,
                username=node.ssh_user,
                password=node.ssh_password,
                key=node.ssh_key,
                command=command,
                timeout=timeout
            )
            
            return result
        except Exception as e:
            logger.error(f"Failed to execute command on {ip}: {e}")
            raise NodeConnectionError(f"Command execution failed: {e}")
    
    async def restart_service(
        self,
        ip: str,
        service: str
    ) -> Dict[str, Any]:
        """Restart a service on node"""
        valid_services = ['agent', 'coredns', 'sniproxy']
        if service not in valid_services:
            raise ValidationError(f"Invalid service. Must be one of {valid_services}")
        
        # Map service names to systemd units
        service_map = {
            'agent': 'dns-proxy-agent',
            'coredns': 'coredns',
            'sniproxy': 'sni-proxy'
        }
        
        systemd_service = service_map[service]
        command = f"systemctl restart {systemd_service}"
        
        result = await self.execute_command(ip, command)
        
        # Update service status
        if result['success']:
            nodes = await state_manager.get('nodes', {})
            if ip in nodes:
                nodes[ip]['status']['services'][service] = ServiceStatus.RUNNING
                await state_manager.set('nodes', nodes)
        
        return result
    
    async def get_service_status(
        self,
        ip: str,
        service: str
    ) -> ServiceStatus:
        """Get service status on node"""
        valid_services = ['agent', 'coredns', 'sniproxy']
        if service not in valid_services:
            raise ValidationError(f"Invalid service. Must be one of {valid_services}")
        
        service_map = {
            'agent': 'dns-proxy-agent',
            'coredns': 'coredns',
            'sniproxy': 'sni-proxy'
        }
        
        systemd_service = service_map[service]
        command = f"systemctl is-active {systemd_service}"
        
        try:
            result = await self.execute_command(ip, command, timeout=10)
            if result['success'] and 'active' in result['output'].lower():
                return ServiceStatus.RUNNING
            else:
                return ServiceStatus.STOPPED
        except Exception:
            return ServiceStatus.UNKNOWN
    
    async def bulk_restart_services(
        self,
        node_ips: List[str],
        services: List[str]
    ) -> Dict[str, Dict[str, Any]]:
        """Restart services on multiple nodes"""
        results = {}
        
        tasks = []
        for ip in node_ips:
            for service in services:
                tasks.append(self.restart_service(ip, service))
        
        # Execute in parallel with limited concurrency
        semaphore = asyncio.Semaphore(5)
        
        async def limited_restart(ip, service):
            async with semaphore:
                try:
                    result = await self.restart_service(ip, service)
                    return ip, service, result
                except Exception as e:
                    return ip, service, {'success': False, 'error': str(e)}
        
        restart_tasks = [
            limited_restart(ip, service)
            for ip in node_ips
            for service in services
        ]
        
        restart_results = await asyncio.gather(*restart_tasks)
        
        # Organize results
        for ip, service, result in restart_results:
            if ip not in results:
                results[ip] = {}
            results[ip][service] = result
        
        return results
    
    async def get_node_metrics(self, ip: str) -> Dict[str, Any]:
        """Get node system metrics"""
        commands = {
            'cpu': "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1",
            'memory': "free | grep Mem | awk '{print ($3/$2) * 100.0}'",
            'disk': "df -h / | awk 'NR==2 {print $5}' | sed 's/%//'",
            'uptime': "cat /proc/uptime | awk '{print int($1)}'"
        }
        
        metrics = {}
        for metric, command in commands.items():
            try:
                result = await self.execute_command(ip, command, timeout=10)
                if result['success']:
                    value = result['output'].strip()
                    if metric in ['cpu', 'memory', 'disk']:
                        metrics[f"{metric}_usage"] = float(value)
                    else:
                        metrics[metric] = int(value)
            except Exception as e:
                logger.warning(f"Failed to get {metric} for {ip}: {e}")
                metrics[metric] = None
        
        # Update node status with metrics
        nodes = await state_manager.get('nodes', {})
        if ip in nodes:
            nodes[ip]['status'].update(metrics)
            await state_manager.set('nodes', nodes)
        
        return metrics
    
    def _is_node_online(self, last_heartbeat: Optional[datetime]) -> bool:
        """Check if node is online based on heartbeat"""
        if not last_heartbeat:
            return False
        
        if isinstance(last_heartbeat, str):
            last_heartbeat = datetime.fromisoformat(last_heartbeat.replace('Z', '+00:00'))
        
        time_diff = (datetime.utcnow() - last_heartbeat).total_seconds()
        return time_diff < self.heartbeat_timeout
    
    async def _update_stats(self):
        """Update node statistics"""
        nodes = await state_manager.get('nodes', {})
        stats = await state_manager.get('stats', {})
        
        stats['total_nodes'] = len(nodes)
        stats['last_update'] = datetime.utcnow().isoformat()
        
        await state_manager.set('stats', stats)
    
    async def _update_active_nodes_count(self):
        """Update active nodes count"""
        nodes = await state_manager.get('nodes', {})
        stats = await state_manager.get('stats', {})
        
        active_count = sum(
            1 for node in nodes.values()
            if self._is_node_online(node.get('status', {}).get('last_heartbeat'))
        )
        
        stats['active_nodes'] = active_count
        await state_manager.set('stats', stats)
