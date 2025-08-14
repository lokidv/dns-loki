from fastapi import FastAPI

from .core.exceptions import install_exception_handlers
from .routers.monitoring import router as monitoring_router


def wire_routers(app: FastAPI) -> FastAPI:
    """Attach built-in routers and exception handlers.

    Kept minimal for Phase 1 to avoid behavior changes. Can be extended later.
    """
    # Routers
    app.include_router(monitoring_router)

    # Exception handlers
    install_exception_handlers(app)

    return app
