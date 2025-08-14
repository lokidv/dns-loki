"""
Synchronization service for DNS-Loki Controller
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import asyncio
import hashlib
import json

from ..core.database import state_manager, cache_manager
from ..core.logging import get_logger
from ..core.exceptions import SyncError
from ..services.node_service import NodeService
from ..services.client_service import ClientService
from ..services.config_service import ConfigService


logger = get_logger(__name__)


class SyncService:
    """Service for synchronizing data with agents"""
    
    def __init__(self):
        self.node_service = NodeService()
        self.client_service = ClientService()
        self.config_service = ConfigService()
        self.sync_interval = 60  # seconds
        self.sync_timeout = 30  # seconds
    
    async def get_sync_data(self) -> Dict[str, Any]:
        """Get data to sync to agents"""
        # Get configuration
        config = await self.config_service.get_config()
        flags = config.flags.dict()
        
        # Get clients
        clients = await self.client_service.get_all_clients()
        
        # Prepare client lists
        dns_clients = []
        proxy_clients = []
        
        for client in clients:
            if client.active:
                if client.type in ['dns', 'both']:
                    dns_clients.append(str(client.ip))
                if client.type in ['proxy', 'both']:
                    proxy_clients.append(str(client.ip))
        
        # Get nodes
        nodes = await self.node_service.get_all_nodes()
        node_ips = [str(node.ip) for node in nodes]
        
        # Prepare sync data
        sync_data = {
            'version': await self._get_data_version(),
            'timestamp': datetime.utcnow().isoformat(),
            'flags': flags,
            'dns_clients': dns_clients,
            'proxy_clients': proxy_clients,
            'nodes': node_ips,
            'dns_config': config.dns_settings,
            'proxy_config': config.proxy_settings
        }
        
        return sync_data
    
    async def sync_to_agent(self, node_ip: str) -> Dict[str, Any]:
        """Sync data to a specific agent"""
        try:
            # Get sync data
            sync_data = await self.get_sync_data()
            
            # Get node
            node = await self.node_service.get_node(node_ip)
            
            # Check if node needs update
            if await self._is_node_synced(node, sync_data['version']):
                return {
                    'success': True,
                    'message': 'Node already synced',
                    'version': sync_data['version']
                }
            
            # Send sync data to agent (this would be via HTTP in real implementation)
            # For now, we just update the node's sync status
            node.status.last_sync = datetime.utcnow()
            node.status.sync_version = sync_data['version']
            await self.node_service.update_node_status(node_ip, node.status)
            
            logger.info(f"Synced data to agent {node_ip}")
            
            return {
                'success': True,
                'message': 'Sync completed',
                'version': sync_data['version']
            }
        
        except Exception as e:
            logger.error(f"Failed to sync to agent {node_ip}: {e}")
            raise SyncError(f"Sync failed: {e}")
    
    async def sync_all_agents(self) -> Dict[str, Dict[str, Any]]:
        """Sync data to all agents"""
        nodes = await self.node_service.get_all_nodes()
        results = {}
        
        # Create sync tasks
        tasks = []
        for node in nodes:
            if node.status.online:
                tasks.append(self.sync_to_agent(str(node.ip)))
        
        # Execute in parallel with limited concurrency
        semaphore = asyncio.Semaphore(5)
        
        async def limited_sync(node_ip):
            async with semaphore:
                try:
                    result = await self.sync_to_agent(node_ip)
                    return node_ip, result
                except Exception as e:
                    return node_ip, {'success': False, 'error': str(e)}
        
        sync_tasks = [
            limited_sync(str(node.ip))
            for node in nodes
            if node.status.online
        ]
        
        sync_results = await asyncio.gather(*sync_tasks)
        
        # Organize results
        for node_ip, result in sync_results:
            results[node_ip] = result
        
        # Update sync stats
        await self._update_sync_stats(results)
        
        return results
    
    async def force_sync(self) -> Dict[str, Any]:
        """Force sync to all agents"""
        # Increment version to force update
        await self._increment_data_version()
        
        # Sync all agents
        results = await self.sync_all_agents()
        
        success_count = sum(1 for r in results.values() if r.get('success'))
        total_count = len(results)
        
        return {
            'success': success_count == total_count,
            'synced': success_count,
            'failed': total_count - success_count,
            'results': results
        }
    
    async def get_sync_status(self) -> Dict[str, Any]:
        """Get overall sync status"""
        nodes = await self.node_service.get_all_nodes()
        current_version = await self._get_data_version()
        
        synced_nodes = []
        unsynced_nodes = []
        offline_nodes = []
        
        for node in nodes:
            if not node.status.online:
                offline_nodes.append(str(node.ip))
            elif node.status.sync_version == current_version:
                synced_nodes.append(str(node.ip))
            else:
                unsynced_nodes.append(str(node.ip))
        
        # Get last sync time
        stats = await state_manager.get('sync_stats', {})
        last_sync = stats.get('last_sync')
        
        return {
            'current_version': current_version,
            'last_sync': last_sync,
            'synced_nodes': synced_nodes,
            'unsynced_nodes': unsynced_nodes,
            'offline_nodes': offline_nodes,
            'total_nodes': len(nodes),
            'sync_rate': len(synced_nodes) / len(nodes) if nodes else 0
        }
    
    async def check_agent_sync(self, node_ip: str) -> Dict[str, Any]:
        """Check if specific agent is synced"""
        node = await self.node_service.get_node(node_ip)
        current_version = await self._get_data_version()
        
        is_synced = node.status.sync_version == current_version
        
        return {
            'node_ip': node_ip,
            'is_synced': is_synced,
            'node_version': node.status.sync_version,
            'current_version': current_version,
            'last_sync': node.status.last_sync.isoformat() if node.status.last_sync else None,
            'online': node.status.online
        }
    
    async def get_pending_changes(self) -> Dict[str, Any]:
        """Get pending changes that need to be synced"""
        flags = await state_manager.get('flags', {})
        
        pending = []
        
        # Check for client updates
        if 'clients_updated' in flags:
            updated_at = datetime.fromisoformat(flags['clients_updated'].replace('Z', '+00:00'))
            if (datetime.utcnow() - updated_at).total_seconds() < 300:
                pending.append({
                    'type': 'clients',
                    'updated_at': updated_at.isoformat(),
                    'age_seconds': int((datetime.utcnow() - updated_at).total_seconds())
                })
        
        # Check for config updates
        if 'config_updated' in flags:
            updated_at = datetime.fromisoformat(flags['config_updated'].replace('Z', '+00:00'))
            if (datetime.utcnow() - updated_at).total_seconds() < 300:
                pending.append({
                    'type': 'config',
                    'updated_at': updated_at.isoformat(),
                    'age_seconds': int((datetime.utcnow() - updated_at).total_seconds())
                })
        
        return {
            'has_pending': len(pending) > 0,
            'pending_changes': pending,
            'total_pending': len(pending)
        }
    
    async def start_auto_sync(self):
        """Start automatic sync process"""
        logger.info("Starting auto-sync service")
        
        while True:
            try:
                # Check for pending changes
                pending = await self.get_pending_changes()
                
                if pending['has_pending']:
                    logger.info(f"Found {pending['total_pending']} pending changes, syncing...")
                    await self.sync_all_agents()
                
                # Wait for next sync interval
                await asyncio.sleep(self.sync_interval)
            
            except Exception as e:
                logger.error(f"Auto-sync error: {e}")
                await asyncio.sleep(10)  # Wait before retry
    
    async def _get_data_version(self) -> str:
        """Get current data version"""
        version_data = await state_manager.get('data_version', {})
        
        if not version_data:
            # Initialize version
            version_data = {
                'version': 1,
                'updated_at': datetime.utcnow().isoformat()
            }
            await state_manager.set('data_version', version_data)
        
        return str(version_data['version'])
    
    async def _increment_data_version(self):
        """Increment data version"""
        version_data = await state_manager.get('data_version', {})
        
        current_version = version_data.get('version', 0)
        version_data['version'] = current_version + 1
        version_data['updated_at'] = datetime.utcnow().isoformat()
        
        await state_manager.set('data_version', version_data)
        
        logger.debug(f"Data version incremented to {version_data['version']}")
    
    async def _is_node_synced(self, node, current_version: str) -> bool:
        """Check if node is synced with current version"""
        return node.status.sync_version == current_version
    
    async def _update_sync_stats(self, results: Dict[str, Dict[str, Any]]):
        """Update sync statistics"""
        stats = await state_manager.get('sync_stats', {})
        
        success_count = sum(1 for r in results.values() if r.get('success'))
        total_count = len(results)
        
        stats['last_sync'] = datetime.utcnow().isoformat()
        stats['last_sync_success'] = success_count
        stats['last_sync_total'] = total_count
        stats['last_sync_rate'] = success_count / total_count if total_count > 0 else 0
        
        # Update rolling stats
        if 'sync_history' not in stats:
            stats['sync_history'] = []
        
        stats['sync_history'].append({
            'timestamp': datetime.utcnow().isoformat(),
            'success': success_count,
            'total': total_count
        })
        
        # Keep only last 100 sync records
        if len(stats['sync_history']) > 100:
            stats['sync_history'] = stats['sync_history'][-100:]
        
        await state_manager.set('sync_stats', stats)
