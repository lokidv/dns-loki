from fastapi import APIRouter
import time

START_TS = time.time()

router = APIRouter(prefix="", tags=["monitoring"])


@router.get("/healthz")
def healthz():
    return {
        "ok": True,
        "ts": time.time(),
        "uptime": round(time.time() - START_TS, 3),
    }


@router.get("/readyz")
def readyz():
    # In later phases we can verify dependent services and return 503 when not ready
    return {"ok": True}
