"""
Database service for DNS-Loki Controller
Manages database initialization and operations
"""

import asyncio
from typing import Dict, Any, Optional
from ..core.database import state_manager
from ..core.logging import get_logger


logger = get_logger(__name__)


class DatabaseService:
    """Service for database operations"""
    
    def __init__(self):
        self.initialized = False
    
    async def initialize(self):
        """Initialize database service"""
        try:
            logger.info("Initializing database service...")
            await state_manager.initialize()
            self.initialized = True
            logger.info("Database service initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize database service: {e}")
            raise
    
    async def close(self):
        """Close database connections"""
        try:
            logger.info("Closing database service...")
            # Save final state
            await state_manager.save()
            logger.info("Database service closed")
        except Exception as e:
            logger.error(f"Error closing database service: {e}")
    
    async def health_check(self) -> Dict[str, Any]:
        """Check database health"""
        try:
            # Test state manager operations
            test_key = "_health_check"
            await state_manager.set(test_key, "ok", save=False)
            result = await state_manager.get(test_key)
            await state_manager.delete(test_key, save=False)
            
            return {
                "status": "healthy" if result == "ok" else "unhealthy",
                "initialized": self.initialized,
                "state_file": str(state_manager.state_file)
            }
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "initialized": self.initialized
            }
    
    async def backup_state(self, backup_path: Optional[str] = None) -> bool:
        """Create backup of current state"""
        try:
            import shutil
            from datetime import datetime
            
            if not backup_path:
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                backup_path = f"{state_manager.state_file}.backup.{timestamp}"
            
            # Force save current state
            await state_manager.save()
            
            # Copy to backup location
            shutil.copy2(state_manager.state_file, backup_path)
            logger.info(f"State backed up to {backup_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to backup state: {e}")
            return False
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            state = await state_manager.get_all()
            return {
                "total_keys": len(state),
                "state_file_size": state_manager.state_file.stat().st_size if state_manager.state_file.exists() else 0,
                "last_modified": state.get("_metadata", {}).get("last_updated"),
                "version": state.get("_metadata", {}).get("version")
            }
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            return {"error": str(e)}
