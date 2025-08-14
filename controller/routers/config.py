"""
Configuration API router for DNS-Loki Controller
"""

from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse

from ..services.config_service import ConfigService
from ..services.auth_service import AuthService
from ..models.config import Config, ConfigUpdate, Flags, DNSConfig, ProxyConfig
from ..models.auth import User
from ..core.dependencies import get_current_user, require_permission


router = APIRouter(prefix="/api/v1/config", tags=["config"])
config_service = ConfigService()
auth_service = AuthService()


@router.get("/", response_model=Config)
async def get_config(
    current_user: User = Depends(get_current_user)
):
    """Get current configuration"""
    try:
        config = await config_service.get_config()
        return config
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/", response_model=Config)
async def update_config(
    update_data: ConfigUpdate,
    current_user: User = Depends(require_permission("manage_config"))
):
    """Update configuration"""
    try:
        config = await config_service.update_config(update_data)
        return config
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/flags", response_model=Flags)
async def get_flags(
    current_user: User = Depends(get_current_user)
):
    """Get system flags"""
    try:
        flags = await config_service.get_flags()
        return flags
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/flags", response_model=Flags)
async def update_flags(
    flags: Dict[str, Any],
    current_user: User = Depends(require_permission("manage_config"))
):
    """Update system flags"""
    try:
        updated_flags = await config_service.update_flags(flags)
        return updated_flags
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/dns", response_model=DNSConfig)
async def get_dns_config(
    current_user: User = Depends(get_current_user)
):
    """Get DNS configuration"""
    try:
        dns_config = await config_service.get_dns_config()
        return dns_config
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/dns", response_model=DNSConfig)
async def update_dns_config(
    dns_config: DNSConfig,
    current_user: User = Depends(require_permission("manage_config"))
):
    """Update DNS configuration"""
    try:
        updated_config = await config_service.update_dns_config(dns_config)
        return updated_config
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/proxy", response_model=ProxyConfig)
async def get_proxy_config(
    current_user: User = Depends(get_current_user)
):
    """Get proxy configuration"""
    try:
        proxy_config = await config_service.get_proxy_config()
        return proxy_config
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/proxy", response_model=ProxyConfig)
async def update_proxy_config(
    proxy_config: ProxyConfig,
    current_user: User = Depends(require_permission("manage_config"))
):
    """Update proxy configuration"""
    try:
        updated_config = await config_service.update_proxy_config(proxy_config)
        return updated_config
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/reset")
async def reset_config(
    current_user: User = Depends(require_permission("manage_config"))
):
    """Reset configuration to defaults"""
    try:
        config = await config_service.reset_config()
        return config
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/backups")
async def list_backups(
    current_user: User = Depends(require_permission("manage_config"))
):
    """List configuration backups"""
    try:
        backups = await config_service.list_backups()
        return backups
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/restore/{backup_name}")
async def restore_config(
    backup_name: str,
    current_user: User = Depends(require_permission("manage_config"))
):
    """Restore configuration from backup"""
    try:
        config = await config_service.restore_config(backup_name)
        return config
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/export")
async def export_config(
    current_user: User = Depends(require_permission("manage_config"))
):
    """Export configuration for backup/migration"""
    try:
        data = await config_service.export_config()
        return data
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/import")
async def import_config(
    data: Dict[str, Any],
    current_user: User = Depends(require_permission("manage_config"))
):
    """Import configuration from backup/migration"""
    try:
        config = await config_service.import_config(data)
        return config
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/validate")
async def validate_config(
    config: Config,
    current_user: User = Depends(get_current_user)
):
    """Validate configuration"""
    try:
        result = await config_service.validate_config(config)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
