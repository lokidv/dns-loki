"""
DNS-Loki Controller Main Application
"""

import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .core.config import settings
from .core.logging import setup_logging, logger
from .core.exceptions import (
    DNSLokiException,
    ValidationError,
    NotFoundError,
    AuthenticationError,
    AuthorizationError
)

# Import routers
from .routers import (
    auth,
    nodes,
    clients,
    config,
    sync,
    monitoring
)

# Import services for initialization
from .services.database_service import DatabaseService
from .services.cache_service import CacheService
from .services.monitoring_service import MonitoringService


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting DNS-Loki Controller...")
    
    # Initialize logging
    setup_logging()
    
    # Initialize database
    db_service = DatabaseService()
    await db_service.initialize()
    
    # Initialize cache
    cache_service = CacheService()
    await cache_service.initialize()
    
    # Start monitoring
    monitoring_service = MonitoringService()
    await monitoring_service.start()
    
    logger.info("DNS-Loki Controller started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down DNS-Loki Controller...")
    
    # Stop monitoring
    await monitoring_service.stop()
    
    # Close cache connections
    await cache_service.close()
    
    # Close database connections
    await db_service.close()
    
    logger.info("DNS-Loki Controller shut down")


# Create FastAPI application
app = FastAPI(
    title="DNS-Loki Controller",
    description="DNS and Proxy Management System",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)


# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Add trusted host middleware
if settings.ALLOWED_HOSTS:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.ALLOWED_HOSTS
    )


# Exception handlers
@app.exception_handler(DNSLokiException)
async def dnsloki_exception_handler(request: Request, exc: DNSLokiException):
    """Handle custom DNS-Loki exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.error_code,
            "message": str(exc),
            "details": exc.details
        }
    )


@app.exception_handler(ValidationError)
async def validation_error_handler(request: Request, exc: ValidationError):
    """Handle validation errors"""
    return JSONResponse(
        status_code=400,
        content={
            "error": "VALIDATION_ERROR",
            "message": str(exc),
            "details": exc.details
        }
    )


@app.exception_handler(NotFoundError)
async def not_found_error_handler(request: Request, exc: NotFoundError):
    """Handle not found errors"""
    return JSONResponse(
        status_code=404,
        content={
            "error": "NOT_FOUND",
            "message": str(exc)
        }
    )


@app.exception_handler(AuthenticationError)
async def authentication_error_handler(request: Request, exc: AuthenticationError):
    """Handle authentication errors"""
    return JSONResponse(
        status_code=401,
        content={
            "error": "AUTHENTICATION_ERROR",
            "message": str(exc)
        }
    )


@app.exception_handler(AuthorizationError)
async def authorization_error_handler(request: Request, exc: AuthorizationError):
    """Handle authorization errors"""
    return JSONResponse(
        status_code=403,
        content={
            "error": "AUTHORIZATION_ERROR",
            "message": str(exc)
        }
    )


# Include routers
app.include_router(auth.router)
app.include_router(nodes.router)
app.include_router(clients.router)
app.include_router(config.router)
app.include_router(sync.router)
app.include_router(monitoring.router)


# Mount static files for UI
app.mount("/", StaticFiles(directory="ui", html=True), name="ui")


# Root endpoint
@app.get("/api")
async def root():
    """API root endpoint"""
    return {
        "name": "DNS-Loki Controller API",
        "version": "2.0.0",
        "status": "operational",
        "endpoints": {
            "auth": "/api/v1/auth",
            "nodes": "/api/v1/nodes",
            "clients": "/api/v1/clients",
            "config": "/api/v1/config",
            "sync": "/api/v1/sync",
            "monitoring": "/api/v1/monitoring",
            "docs": "/api/docs",
            "redoc": "/api/redoc"
        }
    }


# Health check endpoint
@app.get("/health")
async def health_check():
    """Basic health check"""
    return {
        "status": "healthy",
        "service": "dns-loki-controller",
        "version": "2.0.0"
    }


# Metrics endpoint for Prometheus
@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    monitoring_service = MonitoringService()
    metrics_data = await monitoring_service.get_prometheus_metrics()
    return metrics_data


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "controller.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )
