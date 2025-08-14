"""
API Routers for DNS-Loki Controller
"""

from .auth import router as auth_router
from .nodes import router as nodes_router
from .clients import router as clients_router
from .config import router as config_router
from .sync import router as sync_router
from .monitoring import router as monitoring_router

__all__ = [
    "auth_router",
    "nodes_router", 
    "clients_router",
    "config_router",
    "sync_router",
    "monitoring_router"
]
