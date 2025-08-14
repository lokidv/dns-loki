"""
Authentication API router for DNS-Loki Controller
"""

from typing import Optional, Dict, Any
from datetime import timedelta
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm

from ..services.auth_service import AuthService
from ..models.auth import User, UserCreate, UserUpdate, Token, PasswordChange
from ..core.dependencies import get_current_user, require_permission
from ..core.config import settings


router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
auth_service = AuthService()


@router.post("/register", response_model=User)
async def register(
    user_data: UserCreate
):
    """Register new user (first user becomes admin)"""
    try:
        user = await auth_service.create_user(user_data)
        return user
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """Login with username and password"""
    try:
        user = await auth_service.authenticate_user(form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = await auth_service.create_access_token(
            data={"sub": user.username}, 
            expires_delta=access_token_expires
        )
        
        return {"access_token": access_token, "token_type": "bearer"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user)
):
    """Logout current user"""
    try:
        result = await auth_service.logout_user(current_user.username)
        return {"success": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/me", response_model=User)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """Get current user information"""
    return current_user


@router.put("/me", response_model=User)
async def update_current_user(
    update_data: UserUpdate,
    current_user: User = Depends(get_current_user)
):
    """Update current user information"""
    try:
        user = await auth_service.update_user(current_user.username, update_data)
        return user
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/change-password")
async def change_password(
    password_data: PasswordChange,
    current_user: User = Depends(get_current_user)
):
    """Change current user password"""
    try:
        # Verify old password
        user = await auth_service.authenticate_user(
            current_user.username, 
            password_data.old_password
        )
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect password"
            )
        
        # Update password
        result = await auth_service.change_password(
            current_user.username,
            password_data.new_password
        )
        return {"success": result}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/refresh", response_model=Token)
async def refresh_token(
    current_user: User = Depends(get_current_user)
):
    """Refresh access token"""
    try:
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = await auth_service.create_access_token(
            data={"sub": current_user.username},
            expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/users", response_model=list[User])
async def list_users(
    current_user: User = Depends(require_permission("manage_users"))
):
    """List all users (admin only)"""
    try:
        users = await auth_service.list_users()
        return users
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/users/{username}", response_model=User)
async def get_user(
    username: str,
    current_user: User = Depends(require_permission("manage_users"))
):
    """Get specific user (admin only)"""
    try:
        user = await auth_service.get_user(username)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/users/{username}", response_model=User)
async def update_user(
    username: str,
    update_data: UserUpdate,
    current_user: User = Depends(require_permission("manage_users"))
):
    """Update user (admin only)"""
    try:
        user = await auth_service.update_user(username, update_data)
        return user
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/users/{username}")
async def delete_user(
    username: str,
    current_user: User = Depends(require_permission("manage_users"))
):
    """Delete user (admin only)"""
    try:
        if username == current_user.username:
            raise HTTPException(status_code=400, detail="Cannot delete yourself")
        
        result = await auth_service.delete_user(username)
        return {"success": result}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/users/{username}/reset-password")
async def reset_user_password(
    username: str,
    new_password: str,
    current_user: User = Depends(require_permission("manage_users"))
):
    """Reset user password (admin only)"""
    try:
        result = await auth_service.change_password(username, new_password)
        return {"success": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/api-keys/generate")
async def generate_api_key(
    name: str,
    expires_in_days: Optional[int] = None,
    current_user: User = Depends(get_current_user)
):
    """Generate new API key"""
    try:
        api_key = await auth_service.generate_api_key(
            current_user.username,
            name,
            expires_in_days
        )
        return api_key
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/api-keys")
async def list_api_keys(
    current_user: User = Depends(get_current_user)
):
    """List user's API keys"""
    try:
        keys = await auth_service.list_api_keys(current_user.username)
        return keys
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: str,
    current_user: User = Depends(get_current_user)
):
    """Revoke API key"""
    try:
        result = await auth_service.revoke_api_key(key_id, current_user.username)
        return {"success": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
