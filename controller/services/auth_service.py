"""
Authentication and authorization service for DNS-Loki Controller
"""

from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import hashlib
import secrets
from jose import jwt
from passlib.context import CryptContext

from ..core.database import state_manager, cache_manager
from ..core.logging import get_logger
from ..core.exceptions import AuthenticationError, AuthorizationError, ValidationError
from ..models.auth import (
    User, UserCreate, UserUpdate, UserLogin,
    Token, TokenData, APIKey, APIKeyCreate, Session
)


logger = get_logger(__name__)


class AuthService:
    """Service for authentication and authorization"""
    
    def __init__(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.secret_key = self._get_or_create_secret_key()
        self.algorithm = "HS256"
        self.access_token_expire_minutes = 30
        self.refresh_token_expire_days = 7
        self.api_key_length = 32
    
    def _get_or_create_secret_key(self) -> str:
        """Get or create JWT secret key"""
        # In production, this should be stored securely
        return "your-secret-key-change-this-in-production"
    
    async def create_user(self, user_data: UserCreate) -> User:
        """Create a new user"""
        users = await state_manager.get('users', {})
        
        if user_data.username in users:
            raise ValidationError(f"User {user_data.username} already exists")
        
        # Hash password
        hashed_password = self.pwd_context.hash(user_data.password)
        
        # Create user
        user = User(
            username=user_data.username,
            email=user_data.email,
            full_name=user_data.full_name,
            roles=user_data.roles,
            is_active=user_data.is_active,
            is_superuser=user_data.is_superuser,
            hashed_password=hashed_password,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        # Save to state
        users[user.username] = user.dict()
        await state_manager.set('users', users)
        
        logger.info(f"Created user: {user.username}")
        return user
    
    async def get_user(self, username: str) -> Optional[User]:
        """Get user by username"""
        users = await state_manager.get('users', {})
        
        if username not in users:
            return None
        
        return User(**users[username])
    
    async def update_user(self, username: str, update_data: UserUpdate) -> User:
        """Update user"""
        users = await state_manager.get('users', {})
        
        if username not in users:
            raise ValidationError(f"User {username} not found")
        
        user_dict = users[username]
        update_dict = update_data.dict(exclude_unset=True)
        
        # Hash password if provided
        if 'password' in update_dict and update_dict['password']:
            update_dict['hashed_password'] = self.pwd_context.hash(update_dict['password'])
            del update_dict['password']
        
        # Update user data
        for key, value in update_dict.items():
            if value is not None:
                user_dict[key] = value
        
        user_dict['updated_at'] = datetime.utcnow().isoformat()
        
        # Save to state
        users[username] = user_dict
        await state_manager.set('users', users)
        
        logger.info(f"Updated user: {username}")
        return User(**user_dict)
    
    async def delete_user(self, username: str) -> bool:
        """Delete user"""
        users = await state_manager.get('users', {})
        
        if username not in users:
            raise ValidationError(f"User {username} not found")
        
        del users[username]
        await state_manager.set('users', users)
        
        # Clear user sessions
        await self._clear_user_sessions(username)
        
        logger.info(f"Deleted user: {username}")
        return True
    
    async def authenticate_user(self, login_data: UserLogin) -> User:
        """Authenticate user with username and password"""
        user = await self.get_user(login_data.username)
        
        if not user:
            raise AuthenticationError("Invalid username or password")
        
        if not self.pwd_context.verify(login_data.password, user.hashed_password):
            raise AuthenticationError("Invalid username or password")
        
        if not user.is_active:
            raise AuthenticationError("User account is disabled")
        
        # Update last login
        users = await state_manager.get('users', {})
        users[user.username]['last_login'] = datetime.utcnow().isoformat()
        await state_manager.set('users', users)
        
        logger.info(f"User authenticated: {user.username}")
        return user
    
    async def create_access_token(self, user: User) -> Token:
        """Create JWT access token"""
        # Token payload
        expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        payload = {
            "sub": user.username,
            "roles": user.roles,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access"
        }
        
        # Create access token
        access_token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
        # Create refresh token
        refresh_expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
        refresh_payload = {
            "sub": user.username,
            "exp": refresh_expire,
            "iat": datetime.utcnow(),
            "type": "refresh"
        }
        refresh_token = jwt.encode(refresh_payload, self.secret_key, algorithm=self.algorithm)
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=self.access_token_expire_minutes * 60
        )
    
    async def verify_token(self, token: str) -> TokenData:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            username = payload.get("sub")
            if username is None:
                raise AuthenticationError("Invalid token")
            
            # Check if user exists and is active
            user = await self.get_user(username)
            if not user or not user.is_active:
                raise AuthenticationError("User not found or inactive")
            
            return TokenData(
                username=username,
                roles=payload.get("roles", []),
                exp=datetime.fromtimestamp(payload.get("exp"))
            )
        
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.JWTError:
            raise AuthenticationError("Invalid token")
    
    async def refresh_access_token(self, refresh_token: str) -> Token:
        """Refresh access token using refresh token"""
        try:
            payload = jwt.decode(refresh_token, self.secret_key, algorithms=[self.algorithm])
            
            if payload.get("type") != "refresh":
                raise AuthenticationError("Invalid refresh token")
            
            username = payload.get("sub")
            if username is None:
                raise AuthenticationError("Invalid refresh token")
            
            # Get user
            user = await self.get_user(username)
            if not user or not user.is_active:
                raise AuthenticationError("User not found or inactive")
            
            # Create new access token
            return await self.create_access_token(user)
        
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Refresh token has expired")
        except jwt.JWTError:
            raise AuthenticationError("Invalid refresh token")
    
    async def create_api_key(self, username: str, key_data: APIKeyCreate) -> APIKey:
        """Create API key for user"""
        user = await self.get_user(username)
        if not user:
            raise ValidationError(f"User {username} not found")
        
        # Generate API key
        key = secrets.token_urlsafe(self.api_key_length)
        
        # Calculate expiration
        expires_at = None
        if key_data.expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=key_data.expires_in_days)
        
        # Create API key object
        api_key = APIKey(
            key=key,
            name=key_data.name,
            description=key_data.description,
            permissions=key_data.permissions,
            expires_at=expires_at,
            created_at=datetime.utcnow()
        )
        
        # Store API key
        api_keys = await state_manager.get('api_keys', {})
        api_keys[key] = {
            **api_key.dict(),
            'username': username
        }
        await state_manager.set('api_keys', api_keys)
        
        # Add to user's API keys
        users = await state_manager.get('users', {})
        if 'api_keys' not in users[username]:
            users[username]['api_keys'] = []
        users[username]['api_keys'].append(key)
        await state_manager.set('users', users)
        
        logger.info(f"Created API key '{key_data.name}' for user {username}")
        return api_key
    
    async def verify_api_key(self, api_key: str) -> Dict[str, Any]:
        """Verify API key"""
        api_keys = await state_manager.get('api_keys', {})
        
        if api_key not in api_keys:
            raise AuthenticationError("Invalid API key")
        
        key_data = api_keys[api_key]
        
        # Check expiration
        if key_data.get('expires_at'):
            expires_at = datetime.fromisoformat(key_data['expires_at'].replace('Z', '+00:00'))
            if datetime.utcnow() > expires_at:
                raise AuthenticationError("API key has expired")
        
        # Get user
        username = key_data.get('username')
        user = await self.get_user(username)
        if not user or not user.is_active:
            raise AuthenticationError("User not found or inactive")
        
        # Update last used
        api_keys[api_key]['last_used'] = datetime.utcnow().isoformat()
        await state_manager.set('api_keys', api_keys)
        
        return {
            'username': username,
            'permissions': key_data.get('permissions', []),
            'key_name': key_data.get('name')
        }
    
    async def revoke_api_key(self, username: str, api_key: str) -> bool:
        """Revoke API key"""
        api_keys = await state_manager.get('api_keys', {})
        
        if api_key not in api_keys:
            raise ValidationError("API key not found")
        
        if api_keys[api_key].get('username') != username:
            raise AuthorizationError("Not authorized to revoke this API key")
        
        # Remove API key
        del api_keys[api_key]
        await state_manager.set('api_keys', api_keys)
        
        # Remove from user's API keys
        users = await state_manager.get('users', {})
        if 'api_keys' in users[username]:
            users[username]['api_keys'] = [
                k for k in users[username]['api_keys'] if k != api_key
            ]
            await state_manager.set('users', users)
        
        logger.info(f"Revoked API key for user {username}")
        return True
    
    async def create_session(self, user: User, ip_address: str, user_agent: str = None) -> Session:
        """Create user session"""
        session_id = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=24)
        
        session = Session(
            session_id=session_id,
            user_id=user.username,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
            is_active=True
        )
        
        # Store session
        sessions = await state_manager.get('sessions', {})
        sessions[session_id] = session.dict()
        await state_manager.set('sessions', sessions)
        
        # Cache session for quick access
        await cache_manager.set(f"session:{session_id}", session.dict(), ttl=86400)
        
        logger.debug(f"Created session for user {user.username}")
        return session
    
    async def verify_session(self, session_id: str) -> Session:
        """Verify user session"""
        # Check cache first
        cached = await cache_manager.get(f"session:{session_id}")
        if cached:
            session = Session(**cached)
        else:
            sessions = await state_manager.get('sessions', {})
            if session_id not in sessions:
                raise AuthenticationError("Invalid session")
            session = Session(**sessions[session_id])
        
        # Check if session is active and not expired
        if not session.is_active:
            raise AuthenticationError("Session is inactive")
        
        if datetime.utcnow() > session.expires_at:
            raise AuthenticationError("Session has expired")
        
        return session
    
    async def invalidate_session(self, session_id: str) -> bool:
        """Invalidate user session"""
        sessions = await state_manager.get('sessions', {})
        
        if session_id in sessions:
            sessions[session_id]['is_active'] = False
            await state_manager.set('sessions', sessions)
        
        # Clear cache
        await cache_manager.delete(f"session:{session_id}")
        
        logger.debug(f"Invalidated session {session_id}")
        return True
    
    async def check_permission(self, user: User, permission: str) -> bool:
        """Check if user has specific permission"""
        # Superuser has all permissions
        if user.is_superuser:
            return True
        
        # Check role-based permissions
        role_permissions = {
            'admin': ['read', 'write', 'delete', 'manage_users', 'manage_nodes', 'manage_clients'],
            'operator': ['read', 'write', 'manage_nodes', 'manage_clients'],
            'viewer': ['read']
        }
        
        user_permissions = set()
        for role in user.roles:
            if role in role_permissions:
                user_permissions.update(role_permissions[role])
        
        return permission in user_permissions
    
    async def require_permission(self, user: User, permission: str):
        """Require user to have specific permission"""
        if not await self.check_permission(user, permission):
            raise AuthorizationError(f"Permission denied: {permission}")
    
    async def _clear_user_sessions(self, username: str):
        """Clear all sessions for a user"""
        sessions = await state_manager.get('sessions', {})
        
        # Find and remove user sessions
        user_sessions = [
            sid for sid, session in sessions.items()
            if session.get('user_id') == username
        ]
        
        for session_id in user_sessions:
            del sessions[session_id]
            await cache_manager.delete(f"session:{session_id}")
        
        await state_manager.set('sessions', sessions)
        
        logger.debug(f"Cleared {len(user_sessions)} sessions for user {username}")
