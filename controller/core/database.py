"""
Database management for DNS-Loki Controller
Handles state persistence and data operations
"""

import json
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
from contextlib import asynccontextmanager
import aiofiles
import aiofiles.os

from .config import config
from .logging import get_logger
from .exceptions import ConfigurationError


logger = get_logger(__name__)


class StateManager:
    """Manages application state persistence"""
    
    def __init__(self, state_file: Optional[Path] = None):
        self.state_file = state_file or config.settings.data_dir / config.settings.state_file
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self._state: Dict[str, Any] = {}
        self._lock = asyncio.Lock()
        self._loaded = False
    
    async def initialize(self):
        """Initialize state manager and load existing state"""
        if not self._loaded:
            await self.load()
            self._loaded = True
    
    async def load(self) -> Dict[str, Any]:
        """Load state from file"""
        async with self._lock:
            try:
                if self.state_file.exists():
                    async with aiofiles.open(self.state_file, 'r') as f:
                        content = await f.read()
                        self._state = json.loads(content) if content else {}
                        logger.info(f"Loaded state from {self.state_file}")
                else:
                    self._state = self._get_default_state()
                    await self.save()
                    logger.info(f"Created new state file at {self.state_file}")
            except Exception as e:
                logger.error(f"Failed to load state: {e}")
                self._state = self._get_default_state()
            
            return self._state
    
    async def save(self) -> bool:
        """Save state to file"""
        async with self._lock:
            try:
                # Add metadata
                self._state['_metadata'] = {
                    'last_updated': datetime.utcnow().isoformat(),
                    'version': '2.0.0'
                }
                
                # Write to temporary file first
                temp_file = self.state_file.with_suffix('.tmp')
                async with aiofiles.open(temp_file, 'w') as f:
                    await f.write(json.dumps(self._state, indent=2, default=str))
                
                # Atomic rename
                await aiofiles.os.rename(temp_file, self.state_file)
                
                logger.debug("State saved successfully")
                return True
            except Exception as e:
                logger.error(f"Failed to save state: {e}")
                return False
    
    async def get(self, key: str, default: Any = None) -> Any:
        """Get value from state"""
        if not self._loaded:
            await self.initialize()
        return self._state.get(key, default)
    
    async def set(self, key: str, value: Any, save: bool = True) -> bool:
        """Set value in state"""
        if not self._loaded:
            await self.initialize()
        
        async with self._lock:
            self._state[key] = value
            if save:
                return await self.save()
            return True
    
    async def update(self, data: Dict[str, Any], save: bool = True) -> bool:
        """Update multiple values in state"""
        if not self._loaded:
            await self.initialize()
        
        async with self._lock:
            self._state.update(data)
            if save:
                return await self.save()
            return True
    
    async def delete(self, key: str, save: bool = True) -> bool:
        """Delete key from state"""
        if not self._loaded:
            await self.initialize()
        
        async with self._lock:
            if key in self._state:
                del self._state[key]
                if save:
                    return await self.save()
            return True
    
    async def get_all(self) -> Dict[str, Any]:
        """Get entire state"""
        if not self._loaded:
            await self.initialize()
        return self._state.copy()
    
    async def clear(self, save: bool = True) -> bool:
        """Clear all state"""
        async with self._lock:
            self._state = self._get_default_state()
            if save:
                return await self.save()
            return True
    
    def _get_default_state(self) -> Dict[str, Any]:
        """Get default state structure"""
        return {
            'nodes': {},
            'clients': {},
            'flags': {
                'enforce_dns_clients': True,
                'enforce_proxy_clients': False,
                'git_repo': config.settings.default_git_repo,
                'git_branch': config.settings.default_git_branch,
            },
            'stats': {
                'total_nodes': 0,
                'active_nodes': 0,
                'total_clients': 0,
                'last_sync': None,
            },
            '_metadata': {
                'created': datetime.utcnow().isoformat(),
                'version': '2.0.0'
            }
        }
    
    @asynccontextmanager
    async def transaction(self):
        """Context manager for transactional updates"""
        # Save current state
        backup = self._state.copy()
        try:
            yield self
            # Save changes
            await self.save()
        except Exception as e:
            # Rollback on error
            self._state = backup
            logger.error(f"Transaction failed, rolled back: {e}")
            raise


class CacheManager:
    """Simple in-memory cache with TTL"""
    
    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        async with self._lock:
            if key in self._cache:
                entry = self._cache[key]
                if entry['expires'] > datetime.utcnow().timestamp():
                    return entry['value']
                else:
                    del self._cache[key]
            return None
    
    async def set(self, key: str, value: Any, ttl: int = 300):
        """Set value in cache with TTL in seconds"""
        async with self._lock:
            self._cache[key] = {
                'value': value,
                'expires': datetime.utcnow().timestamp() + ttl
            }
    
    async def delete(self, key: str):
        """Delete key from cache"""
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
    
    async def clear(self):
        """Clear all cache"""
        async with self._lock:
            self._cache.clear()
    
    async def cleanup(self):
        """Remove expired entries"""
        async with self._lock:
            now = datetime.utcnow().timestamp()
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry['expires'] <= now
            ]
            for key in expired_keys:
                del self._cache[key]


# Global instances
state_manager = StateManager()
cache_manager = CacheManager()
