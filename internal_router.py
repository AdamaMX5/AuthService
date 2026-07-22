# internal_router.py
from fastapi import APIRouter, Depends

from auth import verify_internal_api_key

router = APIRouter(prefix="/internal", tags=["internal"])


@router.get("/ping")
async def ping(caller_service: str = Depends(verify_internal_api_key)):
    """Reachability check for service-to-service calls. Requires X-API-Key."""
    return {"status": "ok", "caller_service": caller_service}
