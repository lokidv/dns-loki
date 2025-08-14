#!/usr/bin/env python3
"""
Migration script for DNS-Loki v1 to v2
Migrates existing data to new structure
"""

import json
import os
import sys
import asyncio
from pathlib import Path
from datetime import datetime

# Add controller to path
sys.path.insert(0, '/opt/dns-proxy/controller')

from controller.services.database_service import DatabaseService
from controller.services.node_service import NodeService
from controller.services.client_service import ClientService
from controller.services.config_service import ConfigService
from controller.services.auth_service import AuthService
from controller.models.node import NodeCreate
from controller.models.client import ClientCreate
from controller.models.auth import UserCreate


class DNSLokiMigration:
    """Migration handler for DNS-Loki v1 to v2"""
    
    def __init__(self):
        self.old_state_file = Path("/opt/dns-proxy/controller/state.json")
        self.backup_dir = Path("/opt/dns-proxy/backups")
        self.db_service = DatabaseService()
        self.node_service = NodeService()
        self.client_service = ClientService()
        self.config_service = ConfigService()
        self.auth_service = AuthService()
        
    async def initialize(self):
        """Initialize services"""
        print("Initializing services...")
        await self.db_service.initialize()
        print("✓ Services initialized")
        
    async def backup_existing_data(self):
        """Create backup of existing data"""
        print("Creating backup...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_dir / f"migration_backup_{timestamp}"
        backup_path.mkdir(parents=True, exist_ok=True)
        
        # Backup state file
        if self.old_state_file.exists():
            import shutil
            shutil.copy2(self.old_state_file, backup_path / "state.json")
            print(f"✓ Backed up to {backup_path}")
        
        return backup_path
        
    async def load_old_state(self):
        """Load old state.json file"""
        if not self.old_state_file.exists():
            print("⚠ No existing state.json found")
            return None
            
        print("Loading existing state...")
        with open(self.old_state_file, 'r') as f:
            state = json.load(f)
        print(f"✓ Loaded state with {len(state.get('nodes', []))} nodes and {len(state.get('clients', []))} clients")
        return state
        
    async def migrate_nodes(self, nodes_data):
        """Migrate nodes to new structure"""
        if not nodes_data:
            return
            
        print(f"Migrating {len(nodes_data)} nodes...")
        migrated = 0
        failed = 0
        
        for node_data in nodes_data:
            try:
                # Extract node information
                node_create = NodeCreate(
                    ip=node_data.get('ip'),
                    name=node_data.get('name', f"node-{node_data.get('ip')}"),
                    location=node_data.get('location', 'Unknown'),
                    ssh_user=node_data.get('ssh_user', 'root'),
                    ssh_password=node_data.get('ssh_password', ''),
                    ssh_port=node_data.get('ssh_port', 22),
                    ssh_key=node_data.get('ssh_key', ''),
                    roles=node_data.get('roles', ['dns', 'proxy']),
                    metadata={
                        'migrated_from': 'v1',
                        'migration_date': datetime.now().isoformat(),
                        'original_data': node_data
                    }
                )
                
                # Create node in new system
                await self.node_service.create_node(node_create)
                
                # Update status if available
                if node_data.get('last_heartbeat'):
                    await self.node_service.record_heartbeat(
                        node_data['ip'],
                        node_data.get('agent_version', 'unknown')
                    )
                
                migrated += 1
                print(f"  ✓ Migrated node: {node_data['ip']}")
                
            except Exception as e:
                failed += 1
                print(f"  ✗ Failed to migrate node {node_data.get('ip', 'unknown')}: {e}")
                
        print(f"Nodes migration complete: {migrated} succeeded, {failed} failed")
        
    async def migrate_clients(self, clients_data):
        """Migrate clients to new structure"""
        if not clients_data:
            return
            
        print(f"Migrating {len(clients_data)} clients...")
        migrated = 0
        failed = 0
        
        for client_data in clients_data:
            try:
                # Handle both string (IP only) and dict formats
                if isinstance(client_data, str):
                    client_ip = client_data
                    client_info = {'ip': client_ip}
                else:
                    client_ip = client_data.get('ip', client_data.get('client_ip'))
                    client_info = client_data
                
                client_create = ClientCreate(
                    ip=client_ip,
                    name=client_info.get('name', f"client-{client_ip}"),
                    type=client_info.get('type', 'both'),
                    active=client_info.get('active', True),
                    description=client_info.get('description', ''),
                    metadata={
                        'migrated_from': 'v1',
                        'migration_date': datetime.now().isoformat(),
                        'original_data': client_info
                    }
                )
                
                # Create client in new system
                await self.client_service.create_client(client_create)
                migrated += 1
                print(f"  ✓ Migrated client: {client_ip}")
                
            except Exception as e:
                failed += 1
                print(f"  ✗ Failed to migrate client: {e}")
                
        print(f"Clients migration complete: {migrated} succeeded, {failed} failed")
        
    async def migrate_config(self, config_data):
        """Migrate configuration to new structure"""
        if not config_data:
            return
            
        print("Migrating configuration...")
        
        try:
            # Extract flags
            flags = {
                'enforce_dns_clients': config_data.get('enforce_dns_clients', True),
                'enable_monitoring': config_data.get('enable_monitoring', True),
                'debug_mode': config_data.get('debug_mode', False),
                'auto_sync': config_data.get('auto_sync', True),
                'sync_interval': config_data.get('sync_interval', 300)
            }
            
            await self.config_service.update_flags(flags)
            
            # Extract DNS config
            dns_config = {
                'upstream_servers': config_data.get('dns_servers', ['8.8.8.8', '8.8.4.4']),
                'cache_size': config_data.get('cache_size', 10000),
                'ttl': config_data.get('ttl', 300)
            }
            
            await self.config_service.update_dns_config(dns_config)
            
            # Extract proxy config
            proxy_config = {
                'port': config_data.get('proxy_port', 443),
                'workers': config_data.get('workers', 4),
                'timeout': config_data.get('timeout', 30)
            }
            
            await self.config_service.update_proxy_config(proxy_config)
            
            print("✓ Configuration migrated successfully")
            
        except Exception as e:
            print(f"✗ Failed to migrate configuration: {e}")
            
    async def create_default_admin(self):
        """Create default admin user if none exists"""
        print("Creating default admin user...")
        
        try:
            # Check if any users exist
            users = await self.auth_service.list_users()
            if users:
                print("✓ Users already exist, skipping admin creation")
                return
                
            # Create default admin
            admin_data = UserCreate(
                username="admin",
                email="admin@localhost",
                password="admin123",
                full_name="Administrator",
                is_admin=True
            )
            
            await self.auth_service.create_user(admin_data)
            print("✓ Created default admin user (username: admin, password: admin123)")
            print("  ⚠ Please change the password after first login!")
            
        except Exception as e:
            print(f"✗ Failed to create admin user: {e}")
            
    async def run(self):
        """Run the migration"""
        print("\n" + "="*50)
        print("DNS-Loki Migration v1 to v2")
        print("="*50 + "\n")
        
        try:
            # Initialize services
            await self.initialize()
            
            # Backup existing data
            backup_path = await self.backup_existing_data()
            
            # Load old state
            old_state = await self.load_old_state()
            
            if old_state:
                # Migrate nodes
                await self.migrate_nodes(old_state.get('nodes', []))
                
                # Migrate clients
                await self.migrate_clients(old_state.get('clients', []))
                
                # Migrate configuration
                await self.migrate_config(old_state)
            
            # Create default admin
            await self.create_default_admin()
            
            print("\n" + "="*50)
            print("✓ Migration completed successfully!")
            print("="*50)
            
            if backup_path:
                print(f"\nBackup saved to: {backup_path}")
            
            print("\nNext steps:")
            print("1. Review the migrated data in the web UI")
            print("2. Update agent configurations if needed")
            print("3. Test the system functionality")
            print("4. Remove old state.json after verification")
            
        except Exception as e:
            print(f"\n✗ Migration failed: {e}")
            print("Please check the logs and try again")
            sys.exit(1)
        finally:
            await self.db_service.close()


if __name__ == "__main__":
    migration = DNSLokiMigration()
    asyncio.run(migration.run())
