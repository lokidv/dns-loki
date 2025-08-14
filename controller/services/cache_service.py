"""
Cache service for DNS-Loki Controller
Manages caching operations and cleanup
"""

import asyncio
from typing import Dict, Any, Optional
from ..core.database import cache_manager
from ..core.logging import get_logger


logger = get_logger(__name__)


class CacheService:
    """Service for cache operations"""
    
    def __init__(self):
        self.initialized = False
        self._cleanup_task: Optional[asyncio.Task] = None
    
    async def initialize(self):
        """Initialize cache service"""
        try:
            logger.info("Initializing cache service...")
            # Start cleanup task
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            self.initialized = True
            logger.info("Cache service initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize cache service: {e}")
            raise
    
    async def close(self):
        """Close cache service"""
        try:
            logger.info("Closing cache service...")
            
            # Cancel cleanup task
            if self._cleanup_task and not self._cleanup_task.done():
                self._cleanup_task.cancel()
                try:
                    await self._cleanup_task
                except asyncio.CancelledError:
                    pass
            
            # Clear cache
            await cache_manager.clear()
            logger.info("Cache service closed")
        except Exception as e:
            logger.error(f"Error closing cache service: {e}")
    
    async def health_check(self) -> Dict[str, Any]:
        """Check cache health"""
        try:
            # Test cache operations
            test_key = "_health_check"
            await cache_manager.set(test_key, "ok", ttl=5)
            result = await cache_manager.get(test_key)
            await cache_manager.delete(test_key)
            
            return {
                "status": "healthy" if result == "ok" else "unhealthy",
                "initialized": self.initialized,
                "cleanup_task_running": self._cleanup_task and not self._cleanup_task.done()
            }
        except Exception as e:
            logger.error(f"Cache health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "initialized": self.initialized
            }
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            # Access private cache for stats
            cache_data = cache_manager._cache
            total_entries = len(cache_data)
            
            # Count expired entries
            from datetime import datetime
            now = datetime.utcnow().timestamp()
            expired_count = sum(1 for entry in cache_data.values() if entry['expires'] <= now)
            
            return {
                "total_entries": total_entries,
                "active_entries": total_entries - expired_count,
                "expired_entries": expired_count,
                "memory_usage_estimate": sum(len(str(entry)) for entry in cache_data.values())
            }
        except Exception as e:
            logger.error(f"Failed to get cache stats: {e}")
            return {"error": str(e)}
    
    async def clear_cache(self) -> bool:
        """Clear all cache entries"""
        try:
            await cache_manager.clear()
            logger.info("Cache cleared successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to clear cache: {e}")
            return False
    
    async def _cleanup_loop(self):
        """Background task to cleanup expired cache entries"""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                await cache_manager.cleanup()
                logger.debug("Cache cleanup completed")
            except asyncio.CancelledError:
                logger.info("Cache cleanup task cancelled")
                break
            except Exception as e:
                logger.error(f"Error in cache cleanup: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retry
