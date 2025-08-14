"""
Configuration management service for DNS-Loki Controller
"""

from typing import Dict, Any, Optional
from datetime import datetime
import json
from pathlib import Path

from ..core.database import state_manager, cache_manager
from ..core.logging import get_logger
from ..core.exceptions import ValidationError
from ..models.config import Config, ConfigUpdate, Flags, DNSConfig, ProxyConfig


logger = get_logger(__name__)


class ConfigService:
    """Service for managing system configuration"""
    
    def __init__(self):
        self.config_file = Path("/opt/dns-proxy/controller/config.json")
        self.backup_dir = Path("/opt/dns-proxy/controller/backups")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    async def get_config(self) -> Config:
        """Get current configuration"""
        # Check cache first
        cached = await cache_manager.get("system_config")
        if cached:
            return Config(**cached)
        
        # Load from state
        config_data = await state_manager.get('config', {})
        
        if not config_data:
            # Initialize with defaults
            config = Config()
            await self.save_config(config)
            return config
        
        config = Config(**config_data)
        
        # Cache for 5 minutes
        await cache_manager.set("system_config", config.dict(), ttl=300)
        
        return config
    
    async def update_config(self, update_data: ConfigUpdate) -> Config:
        """Update configuration"""
        config = await self.get_config()
        
        # Backup current config
        await self._backup_config(config)
        
        # Apply updates
        update_dict = update_data.dict(exclude_unset=True)
        
        if 'flags' in update_dict and update_dict['flags']:
            config.flags = Flags(**{**config.flags.dict(), **update_dict['flags']})
        
        if 'dns_settings' in update_dict:
            config.dns_settings.update(update_dict['dns_settings'])
        
        if 'proxy_settings' in update_dict:
            config.proxy_settings.update(update_dict['proxy_settings'])
        
        if 'network_settings' in update_dict:
            config.network_settings.update(update_dict['network_settings'])
        
        if 'monitoring_settings' in update_dict:
            config.monitoring_settings.update(update_dict['monitoring_settings'])
        
        config.updated_at = datetime.utcnow()
        
        # Save updated config
        await self.save_config(config)
        
        # Trigger sync to agents
        await self._trigger_sync()
        
        logger.info("Configuration updated")
        return config
    
    async def save_config(self, config: Config):
        """Save configuration to state and file"""
        config_dict = config.dict()
        
        # Save to state
        await state_manager.set('config', config_dict)
        
        # Clear cache
        await cache_manager.delete("system_config")
        
        # Save to file
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config_dict, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save config to file: {e}")
    
    async def load_config_from_file(self) -> Config:
        """Load configuration from file"""
        if not self.config_file.exists():
            logger.warning("Config file not found, using defaults")
            return Config()
        
        try:
            with open(self.config_file, 'r') as f:
                config_data = json.load(f)
            
            config = Config(**config_data)
            
            # Save to state
            await state_manager.set('config', config.dict())
            
            return config
        except Exception as e:
            logger.error(f"Failed to load config from file: {e}")
            return Config()
    
    async def get_flags(self) -> Flags:
        """Get system flags"""
        config = await self.get_config()
        return config.flags
    
    async def update_flags(self, flags: Dict[str, Any]) -> Flags:
        """Update system flags"""
        config = await self.get_config()
        
        # Update flags
        flags_dict = config.flags.dict()
        flags_dict.update(flags)
        config.flags = Flags(**flags_dict)
        
        # Save config
        await self.save_config(config)
        
        # Trigger sync
        await self._trigger_sync()
        
        logger.info(f"Flags updated: {flags}")
        return config.flags
    
    async def get_dns_config(self) -> DNSConfig:
        """Get DNS configuration"""
        config = await self.get_config()
        
        if 'dns' in config.dns_settings:
            return DNSConfig(**config.dns_settings['dns'])
        
        return DNSConfig()
    
    async def update_dns_config(self, dns_config: DNSConfig) -> DNSConfig:
        """Update DNS configuration"""
        config = await self.get_config()
        config.dns_settings['dns'] = dns_config.dict()
        
        await self.save_config(config)
        await self._trigger_sync()
        
        logger.info("DNS configuration updated")
        return dns_config
    
    async def get_proxy_config(self) -> ProxyConfig:
        """Get proxy configuration"""
        config = await self.get_config()
        
        if 'proxy' in config.proxy_settings:
            return ProxyConfig(**config.proxy_settings['proxy'])
        
        return ProxyConfig()
    
    async def update_proxy_config(self, proxy_config: ProxyConfig) -> ProxyConfig:
        """Update proxy configuration"""
        config = await self.get_config()
        config.proxy_settings['proxy'] = proxy_config.dict()
        
        await self.save_config(config)
        await self._trigger_sync()
        
        logger.info("Proxy configuration updated")
        return proxy_config
    
    async def reset_config(self) -> Config:
        """Reset configuration to defaults"""
        # Backup current config
        current = await self.get_config()
        await self._backup_config(current)
        
        # Create new default config
        config = Config()
        
        # Save
        await self.save_config(config)
        
        # Trigger sync
        await self._trigger_sync()
        
        logger.info("Configuration reset to defaults")
        return config
    
    async def restore_config(self, backup_name: str) -> Config:
        """Restore configuration from backup"""
        backup_file = self.backup_dir / backup_name
        
        if not backup_file.exists():
            raise ValidationError(f"Backup file not found: {backup_name}")
        
        try:
            with open(backup_file, 'r') as f:
                config_data = json.load(f)
            
            config = Config(**config_data)
            
            # Save restored config
            await self.save_config(config)
            
            # Trigger sync
            await self._trigger_sync()
            
            logger.info(f"Configuration restored from {backup_name}")
            return config
        except Exception as e:
            logger.error(f"Failed to restore config: {e}")
            raise ValidationError(f"Failed to restore configuration: {e}")
    
    async def list_backups(self) -> list:
        """List available configuration backups"""
        backups = []
        
        for backup_file in self.backup_dir.glob("config_*.json"):
            stat = backup_file.stat()
            backups.append({
                'name': backup_file.name,
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat()
            })
        
        # Sort by creation time (newest first)
        backups.sort(key=lambda x: x['created'], reverse=True)
        
        return backups
    
    async def export_config(self) -> Dict[str, Any]:
        """Export configuration for backup/migration"""
        config = await self.get_config()
        
        # Get additional data
        nodes = await state_manager.get('nodes', {})
        clients = await state_manager.get('clients', {})
        
        return {
            'config': config.dict(),
            'nodes': nodes,
            'clients': clients,
            'exported_at': datetime.utcnow().isoformat(),
            'version': '1.0'
        }
    
    async def import_config(self, data: Dict[str, Any]) -> Config:
        """Import configuration from backup/migration"""
        if 'config' not in data:
            raise ValidationError("Invalid import data: missing config")
        
        # Backup current state
        current = await self.get_config()
        await self._backup_config(current)
        
        # Import config
        config = Config(**data['config'])
        await self.save_config(config)
        
        # Import nodes if present
        if 'nodes' in data:
            await state_manager.set('nodes', data['nodes'])
        
        # Import clients if present
        if 'clients' in data:
            await state_manager.set('clients', data['clients'])
        
        # Trigger sync
        await self._trigger_sync()
        
        logger.info("Configuration imported successfully")
        return config
    
    async def validate_config(self, config: Config) -> Dict[str, Any]:
        """Validate configuration"""
        errors = []
        warnings = []
        
        # Validate flags
        if config.flags.update_interval < 10:
            errors.append("Update interval must be at least 10 seconds")
        
        if config.flags.update_interval > 3600:
            warnings.append("Update interval is very high (>1 hour)")
        
        # Validate DNS settings
        if 'dns' in config.dns_settings:
            dns_config = DNSConfig(**config.dns_settings['dns'])
            
            if not dns_config.upstream_servers:
                errors.append("At least one upstream DNS server is required")
            
            if dns_config.cache_ttl < 10:
                warnings.append("DNS cache TTL is very low (<10 seconds)")
        
        # Validate proxy settings
        if 'proxy' in config.proxy_settings:
            proxy_config = ProxyConfig(**config.proxy_settings['proxy'])
            
            if proxy_config.listen_port < 1 or proxy_config.listen_port > 65535:
                errors.append("Invalid proxy listen port")
            
            if proxy_config.max_connections < 10:
                warnings.append("Max connections is very low (<10)")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings
        }
    
    async def _backup_config(self, config: Config):
        """Create a backup of current configuration"""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_dir / f"config_{timestamp}.json"
        
        try:
            with open(backup_file, 'w') as f:
                json.dump(config.dict(), f, indent=2, default=str)
            
            logger.debug(f"Configuration backed up to {backup_file}")
            
            # Clean old backups (keep last 10)
            backups = sorted(self.backup_dir.glob("config_*.json"))
            if len(backups) > 10:
                for old_backup in backups[:-10]:
                    old_backup.unlink()
                    logger.debug(f"Removed old backup: {old_backup}")
        
        except Exception as e:
            logger.error(f"Failed to backup configuration: {e}")
    
    async def _trigger_sync(self):
        """Trigger configuration sync to agents"""
        # Set a flag that agents check
        flags = await state_manager.get('flags', {})
        flags['config_updated'] = datetime.utcnow().isoformat()
        await state_manager.set('flags', flags)
        
        logger.debug("Triggered configuration sync to agents")
