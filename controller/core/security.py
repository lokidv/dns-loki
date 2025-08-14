"""
Security utilities for DNS-Loki Controller
Handles authentication, authorization, and encryption
"""

import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from jose import jwt, JWTError
from passlib.context import CryptContext

from .config import config
from .logging import get_logger
from .exceptions import AuthenticationError, AuthorizationError


logger = get_logger(__name__)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class SecurityManager:
    """Manages security operations"""
    
    def __init__(self):
        self.secret_key = config.settings.secret_key
        self.algorithm = config.settings.jwt_algorithm
        self.expiration_hours = config.settings.jwt_expiration_hours
    
    # Password operations
    def hash_password(self, password: str) -> str:
        """Hash a password"""
        return pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    # Token operations
    def create_access_token(
        self,
        data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create a JWT access token"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(hours=self.expiration_hours)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "jti": secrets.token_urlsafe(16)  # JWT ID for token revocation
        })
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def decode_token(self, token: str) -> Dict[str, Any]:
        """Decode and validate a JWT token"""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )
            return payload
        except JWTError as e:
            logger.warning(f"Invalid token: {e}")
            raise AuthenticationError("Invalid or expired token")
    
    def create_api_key(self, identifier: str) -> str:
        """Create an API key"""
        # Generate random key
        key = secrets.token_urlsafe(32)
        # Create signature
        signature = hmac.new(
            self.secret_key.encode(),
            f"{identifier}:{key}".encode(),
            hashlib.sha256
        ).hexdigest()[:8]
        # Return formatted key
        return f"dnsloki_{key}_{signature}"
    
    def verify_api_key(self, api_key: str, identifier: str) -> bool:
        """Verify an API key"""
        if not api_key.startswith("dnsloki_"):
            return False
        
        try:
            parts = api_key.split("_")
            if len(parts) != 3:
                return False
            
            _, key, provided_signature = parts
            
            # Recreate signature
            expected_signature = hmac.new(
                self.secret_key.encode(),
                f"{identifier}:{key}".encode(),
                hashlib.sha256
            ).hexdigest()[:8]
            
            # Constant time comparison
            return hmac.compare_digest(provided_signature, expected_signature)
        except Exception as e:
            logger.warning(f"API key verification failed: {e}")
            return False
    
    # Session management
    def create_session_token(self, user_id: str, metadata: Optional[Dict] = None) -> str:
        """Create a session token"""
        data = {
            "sub": user_id,
            "type": "session",
            "metadata": metadata or {}
        }
        return self.create_access_token(data)
    
    def validate_session_token(self, token: str) -> Dict[str, Any]:
        """Validate a session token"""
        payload = self.decode_token(token)
        if payload.get("type") != "session":
            raise AuthenticationError("Invalid session token")
        return payload


class RBACManager:
    """Role-Based Access Control Manager"""
    
    # Default roles and permissions
    ROLES = {
        "admin": {
            "description": "Full system access",
            "permissions": ["*"]
        },
        "operator": {
            "description": "Manage nodes and configurations",
            "permissions": [
                "nodes:read",
                "nodes:write",
                "config:read",
                "config:write",
                "clients:read",
                "clients:write"
            ]
        },
        "viewer": {
            "description": "Read-only access",
            "permissions": [
                "nodes:read",
                "config:read",
                "clients:read",
                "stats:read"
            ]
        }
    }
    
    def __init__(self):
        self.roles = self.ROLES.copy()
    
    def check_permission(
        self,
        user_roles: List[str],
        required_permission: str
    ) -> bool:
        """Check if user roles have required permission"""
        for role in user_roles:
            if role in self.roles:
                permissions = self.roles[role]["permissions"]
                
                # Check for wildcard permission
                if "*" in permissions:
                    return True
                
                # Check for exact permission
                if required_permission in permissions:
                    return True
                
                # Check for partial wildcard (e.g., "nodes:*")
                resource = required_permission.split(":")[0]
                if f"{resource}:*" in permissions:
                    return True
        
        return False
    
    def add_role(self, name: str, description: str, permissions: List[str]):
        """Add a custom role"""
        self.roles[name] = {
            "description": description,
            "permissions": permissions
        }
    
    def get_role_permissions(self, role: str) -> List[str]:
        """Get permissions for a role"""
        if role in self.roles:
            return self.roles[role]["permissions"]
        return []
    
    def list_roles(self) -> Dict[str, Dict[str, Any]]:
        """List all available roles"""
        return self.roles.copy()


class AuditLogger:
    """Audit logging for security events"""
    
    def __init__(self):
        self.logger = get_logger("audit")
    
    async def log_event(
        self,
        event_type: str,
        user: Optional[str] = None,
        ip_address: Optional[str] = None,
        resource: Optional[str] = None,
        action: Optional[str] = None,
        result: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log an audit event"""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": event_type,
            "user": user or "system",
            "ip_address": ip_address,
            "resource": resource,
            "action": action,
            "result": result,
            "details": details or {}
        }
        
        self.logger.info(
            f"AUDIT: {event_type}",
            extra={"extra_data": event}
        )
    
    async def log_authentication(
        self,
        user: str,
        ip_address: str,
        success: bool,
        method: str = "password"
    ):
        """Log authentication attempt"""
        await self.log_event(
            event_type="authentication",
            user=user,
            ip_address=ip_address,
            action="login",
            result="success" if success else "failure",
            details={"method": method}
        )
    
    async def log_authorization(
        self,
        user: str,
        resource: str,
        action: str,
        allowed: bool
    ):
        """Log authorization check"""
        await self.log_event(
            event_type="authorization",
            user=user,
            resource=resource,
            action=action,
            result="allowed" if allowed else "denied"
        )
    
    async def log_data_access(
        self,
        user: str,
        resource: str,
        action: str,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log data access"""
        await self.log_event(
            event_type="data_access",
            user=user,
            resource=resource,
            action=action,
            details=details
        )


# Global instances
security_manager = SecurityManager()
rbac_manager = RBACManager()
audit_logger = AuditLogger()
