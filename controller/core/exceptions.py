from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_409_CONFLICT,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

# --- Typed domain exceptions (module-level for importability) ---
class BadRequestError(Exception):
    pass


class UnauthorizedError(Exception):
    pass


class ForbiddenError(Exception):
    pass


class NotFoundError(Exception):
    pass


class ConflictError(Exception):
    pass


class RemoteExecutionError(Exception):
    pass


def install_exception_handlers(app: FastAPI) -> None:
    """Register basic exception handlers.

    Phase 1 keeps it minimal and dependency-free. We can expand in later phases.
    """

    # Typed exceptions are defined at module scope; just register handlers.

    @app.exception_handler(BadRequestError)
    async def _bad_request(request: Request, exc: BadRequestError):  # type: ignore[unused-ignore]
        return JSONResponse(
            status_code=HTTP_400_BAD_REQUEST,
            content={"detail": str(exc) or "Bad Request", "error": "BadRequest"},
        )

    @app.exception_handler(UnauthorizedError)
    async def _unauthorized(request: Request, exc: UnauthorizedError):  # type: ignore[unused-ignore]
        return JSONResponse(
            status_code=HTTP_401_UNAUTHORIZED,
            content={"detail": str(exc) or "Unauthorized", "error": "Unauthorized"},
        )

    @app.exception_handler(ForbiddenError)
    async def _forbidden(request: Request, exc: ForbiddenError):  # type: ignore[unused-ignore]
        return JSONResponse(
            status_code=HTTP_403_FORBIDDEN,
            content={"detail": str(exc) or "Forbidden", "error": "Forbidden"},
        )

    @app.exception_handler(NotFoundError)
    async def _not_found(request: Request, exc: NotFoundError):  # type: ignore[unused-ignore]
        return JSONResponse(
            status_code=HTTP_404_NOT_FOUND,
            content={"detail": str(exc) or "Not Found", "error": "NotFound"},
        )

    @app.exception_handler(ConflictError)
    async def _conflict(request: Request, exc: ConflictError):  # type: ignore[unused-ignore]
        return JSONResponse(
            status_code=HTTP_409_CONFLICT,
            content={"detail": str(exc) or "Conflict", "error": "Conflict"},
        )

    @app.exception_handler(RemoteExecutionError)
    async def _remote_error(request: Request, exc: RemoteExecutionError):  # type: ignore[unused-ignore]
        return JSONResponse(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": str(exc) or "Remote execution error", "error": "RemoteExecutionError"},
        )

    # Map common Python exceptions
    @app.exception_handler(ValueError)
    async def _value_error(request: Request, exc: ValueError):  # type: ignore[unused-ignore]
        return JSONResponse(
            status_code=HTTP_400_BAD_REQUEST,
            content={"detail": str(exc) or "Bad Request", "error": "ValueError"},
        )

    @app.exception_handler(RuntimeError)
    async def _runtime_error(request: Request, exc: RuntimeError):  # type: ignore[unused-ignore]
        return JSONResponse(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": str(exc) or "Runtime error", "error": "RuntimeError"},
        )

    @app.exception_handler(Exception)
    async def _unhandled_exception(request: Request, exc: Exception):  # type: ignore[unused-ignore]
        return JSONResponse(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "Internal Server Error",
                "error": exc.__class__.__name__,
            },
        )
