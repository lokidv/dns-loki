"""
Dependencies for FastAPI routes
"""

from typing import Optional, Callable
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from jose import JWTError, jwt

from ..services.auth_service import AuthService
from ..models.auth import User, TokenData
from ..core.config import settings
from ..core.exceptions import AuthenticationError, AuthorizationError


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
auth_service = AuthService()


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    api_key: Optional[str] = Depends(api_key_header)
) -> User:
    """Get current authenticated user from token or API key"""
    
    # Try API key first if provided
    if api_key:
        try:
            user = await auth_service.validate_api_key(api_key)
            if user:
                return user
        except Exception:
            pass
    
    # Try JWT token
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    user = await auth_service.get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Ensure user is active"""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user


async def get_current_admin_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Ensure user is admin"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user


def require_permission(permission: str) -> Callable:
    """Dependency to require specific permission"""
    
    async def permission_checker(
        current_user: User = Depends(get_current_user)
    ) -> User:
        # Admin has all permissions
        if current_user.is_admin:
            return current_user
        
        # Check specific permission
        if permission not in current_user.permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required"
            )
        
        return current_user
    
    return permission_checker


def require_permissions(*permissions: str) -> Callable:
    """Dependency to require multiple permissions"""
    
    async def permissions_checker(
        current_user: User = Depends(get_current_user)
    ) -> User:
        # Admin has all permissions
        if current_user.is_admin:
            return current_user
        
        # Check all required permissions
        missing = [p for p in permissions if p not in current_user.permissions]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permissions required: {', '.join(missing)}"
            )
        
        return current_user
    
    return permissions_checker


async def get_optional_user(
    token: Optional[str] = Depends(oauth2_scheme),
    api_key: Optional[str] = Depends(api_key_header)
) -> Optional[User]:
    """Get current user if authenticated, None otherwise"""
    
    if not token and not api_key:
        return None
    
    try:
        return await get_current_user(token, api_key)
    except HTTPException:
        return None


class RateLimitDependency:
    """Rate limiting dependency"""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}
    
    async def __call__(self, current_user: User = Depends(get_current_user)):
        """Check rate limit for user"""
        # Implementation would track requests per user
        # For now, just return the user
        return current_user


# Common dependencies
rate_limit = RateLimitDependency()


async def validate_node_access(
    node_ip: str,
    current_user: User = Depends(get_current_user)
) -> bool:
    """Validate user has access to specific node"""
    # Admin has access to all nodes
    if current_user.is_admin:
        return True
    
    # Check if user has specific node access
    # This would be implemented based on your access control model
    return True


async def validate_client_access(
    client_ip: str,
    current_user: User = Depends(get_current_user)
) -> bool:
    """Validate user has access to specific client"""
    # Admin has access to all clients
    if current_user.is_admin:
        return True
    
    # Check if user has specific client access
    # This would be implemented based on your access control model
    return True
