"""
Custom exceptions for DNS-Loki Controller
"""

from typing import Optional, Dict, Any
from fastapi import HTTPException, status


class DNSLokiException(Exception):
    """Base exception for DNS-Loki"""
    
    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.code = code or self.__class__.__name__
        self.details = details or {}
        super().__init__(self.message)


class ConfigurationError(DNSLokiException):
    """Configuration related errors"""
    pass


class NodeNotFoundError(DNSLokiException):
    """Node not found in the system"""
    pass


class NodeConnectionError(DNSLokiException):
    """Failed to connect to node"""
    pass


class AgentError(DNSLokiException):
    """Agent related errors"""
    pass


class AuthenticationError(DNSLokiException):
    """Authentication failed"""
    pass


class AuthorizationError(DNSLokiException):
    """Authorization failed"""
    pass


class ValidationError(DNSLokiException):
    """Data validation error"""
    pass


class SyncError(DNSLokiException):
    """Synchronization error"""
    pass


class ServiceError(DNSLokiException):
    """Service operation error"""
    pass


# HTTP Exceptions
class HTTPNotFound(HTTPException):
    def __init__(self, detail: str = "Resource not found"):
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


class HTTPBadRequest(HTTPException):
    def __init__(self, detail: str = "Bad request"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class HTTPUnauthorized(HTTPException):
    def __init__(self, detail: str = "Unauthorized"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


class HTTPForbidden(HTTPException):
    def __init__(self, detail: str = "Forbidden"):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


class HTTPConflict(HTTPException):
    def __init__(self, detail: str = "Conflict"):
        super().__init__(status_code=status.HTTP_409_CONFLICT, detail=detail)


class HTTPServerError(HTTPException):
    def __init__(self, detail: str = "Internal server error"):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail
        )
