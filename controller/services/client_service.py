"""
Client management service for DNS-Loki Controller
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
import ipaddress

from ..core.database import state_manager, cache_manager
from ..core.logging import get_logger
from ..core.exceptions import ValidationError
from ..models.client import Client, ClientCreate, ClientUpdate, ClientStats


logger = get_logger(__name__)


class ClientService:
    """Service for managing clients"""
    
    async def get_all_clients(self) -> List[Client]:
        """Get all clients"""
        clients_data = await state_manager.get('clients', {})
        return [Client(**data) for data in clients_data.values()]
    
    async def get_client(self, ip: str) -> Client:
        """Get a specific client"""
        clients = await state_manager.get('clients', {})
        
        if ip not in clients:
            raise ValidationError(f"Client {ip} not found")
        
        return Client(**clients[ip])
    
    async def create_client(self, client_data: ClientCreate) -> Client:
        """Create a new client"""
        clients = await state_manager.get('clients', {})
        ip = str(client_data.ip)
        
        # Validate IP address
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValidationError(f"Invalid IP address: {ip}")
        
        if ip in clients:
            raise ValidationError(f"Client {ip} already exists")
        
        # Create client instance
        client = Client(
            **client_data.dict(),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        # Save to state
        clients[ip] = client.dict()
        await state_manager.set('clients', clients)
        
        # Update stats
        await self._update_stats()
        
        # Trigger sync to agents
        await self._trigger_sync()
        
        logger.info(f"Created client {ip}")
        return client
    
    async def update_client(self, ip: str, update_data: ClientUpdate) -> Client:
        """Update a client"""
        clients = await state_manager.get('clients', {})
        
        if ip not in clients:
            raise ValidationError(f"Client {ip} not found")
        
        # Update client data
        client_dict = clients[ip]
        update_dict = update_data.dict(exclude_unset=True)
        
        for key, value in update_dict.items():
            if value is not None:
                client_dict[key] = value
        
        client_dict['updated_at'] = datetime.utcnow().isoformat()
        
        # Save to state
        clients[ip] = client_dict
        await state_manager.set('clients', clients)
        
        # Trigger sync to agents
        await self._trigger_sync()
        
        logger.info(f"Updated client {ip}")
        return Client(**client_dict)
    
    async def delete_client(self, ip: str) -> bool:
        """Delete a client"""
        clients = await state_manager.get('clients', {})
        
        if ip not in clients:
            raise ValidationError(f"Client {ip} not found")
        
        del clients[ip]
        await state_manager.set('clients', clients)
        
        # Update stats
        await self._update_stats()
        
        # Clear cache
        await cache_manager.delete(f"client:{ip}")
        
        # Trigger sync to agents
        await self._trigger_sync()
        
        logger.info(f"Deleted client {ip}")
        return True
    
    async def bulk_create_clients(self, client_ips: List[str]) -> List[Client]:
        """Create multiple clients at once"""
        created_clients = []
        
        for ip in client_ips:
            try:
                client_data = ClientCreate(ip=ip, name=f"client-{ip}")
                client = await self.create_client(client_data)
                created_clients.append(client)
            except ValidationError as e:
                logger.warning(f"Failed to create client {ip}: {e}")
        
        return created_clients
    
    async def bulk_delete_clients(self, client_ips: List[str]) -> Dict[str, bool]:
        """Delete multiple clients at once"""
        results = {}
        
        for ip in client_ips:
            try:
                result = await self.delete_client(ip)
                results[ip] = result
            except Exception as e:
                logger.warning(f"Failed to delete client {ip}: {e}")
                results[ip] = False
        
        return results
    
    async def activate_client(self, ip: str) -> Client:
        """Activate a client"""
        update_data = ClientUpdate(active=True)
        return await self.update_client(ip, update_data)
    
    async def deactivate_client(self, ip: str) -> Client:
        """Deactivate a client"""
        update_data = ClientUpdate(active=False)
        return await self.update_client(ip, update_data)
    
    async def get_active_clients(self) -> List[Client]:
        """Get all active clients"""
        clients = await self.get_all_clients()
        return [c for c in clients if c.active]
    
    async def get_dns_clients(self) -> List[str]:
        """Get list of DNS client IPs"""
        clients = await self.get_active_clients()
        dns_clients = [
            str(c.ip) for c in clients 
            if c.type in ['dns', 'both']
        ]
        return dns_clients
    
    async def get_proxy_clients(self) -> List[str]:
        """Get list of proxy client IPs"""
        clients = await self.get_active_clients()
        proxy_clients = [
            str(c.ip) for c in clients 
            if c.type in ['proxy', 'both']
        ]
        return proxy_clients
    
    async def get_client_stats(self, ip: str) -> ClientStats:
        """Get client statistics"""
        # Check cache first
        cached = await cache_manager.get(f"client_stats:{ip}")
        if cached:
            return ClientStats(**cached)
        
        # TODO: Implement actual stats collection from agents
        # For now, return mock stats
        stats = ClientStats(
            ip=ip,
            total_requests=0,
            blocked_requests=0,
            bandwidth_used=0
        )
        
        # Cache for 1 minute
        await cache_manager.set(f"client_stats:{ip}", stats.dict(), ttl=60)
        
        return stats
    
    async def update_client_stats(self, ip: str, stats: Dict[str, Any]):
        """Update client statistics"""
        # Store in cache
        await cache_manager.set(f"client_stats:{ip}", stats, ttl=300)
        
        # Update last_seen
        clients = await state_manager.get('clients', {})
        if ip in clients:
            clients[ip]['last_seen'] = datetime.utcnow().isoformat()
            await state_manager.set('clients', clients)
    
    async def search_clients(
        self,
        query: Optional[str] = None,
        active_only: bool = False,
        client_type: Optional[str] = None
    ) -> List[Client]:
        """Search clients with filters"""
        clients = await self.get_all_clients()
        
        # Apply filters
        if active_only:
            clients = [c for c in clients if c.active]
        
        if client_type:
            clients = [c for c in clients if c.type == client_type]
        
        if query:
            query_lower = query.lower()
            clients = [
                c for c in clients
                if query_lower in str(c.ip).lower() or
                   (c.name and query_lower in c.name.lower())
            ]
        
        return clients
    
    async def export_clients(self) -> Dict[str, Any]:
        """Export all clients data"""
        clients = await self.get_all_clients()
        return {
            'clients': [c.dict() for c in clients],
            'total': len(clients),
            'active': len([c for c in clients if c.active]),
            'exported_at': datetime.utcnow().isoformat()
        }
    
    async def import_clients(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Import clients data"""
        imported = 0
        failed = 0
        
        for client_data in data.get('clients', []):
            try:
                # Remove timestamps
                client_data.pop('created_at', None)
                client_data.pop('updated_at', None)
                client_data.pop('last_seen', None)
                
                client_create = ClientCreate(**client_data)
                await self.create_client(client_create)
                imported += 1
            except Exception as e:
                logger.warning(f"Failed to import client: {e}")
                failed += 1
        
        return {
            'imported': imported,
            'failed': failed,
            'total': imported + failed
        }
    
    async def _update_stats(self):
        """Update client statistics"""
        clients = await state_manager.get('clients', {})
        stats = await state_manager.get('stats', {})
        
        stats['total_clients'] = len(clients)
        stats['active_clients'] = len([
            c for c in clients.values() 
            if c.get('active', False)
        ])
        
        await state_manager.set('stats', stats)
    
    async def _trigger_sync(self):
        """Trigger sync to agents"""
        # Set a flag that agents check
        flags = await state_manager.get('flags', {})
        flags['clients_updated'] = datetime.utcnow().isoformat()
        await state_manager.set('flags', flags)
        
        logger.debug("Triggered client sync to agents")
