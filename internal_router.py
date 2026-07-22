# internal_router.py
import logging

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, EmailStr
from pymongo.errors import DuplicateKeyError

from auth import create_token, get_password_hash, verify_internal_api_key
from lib.emailApi import send_password_reset_email
from models import User, generate_unique_id

logger = logging.getLogger(__name__)

# Every /internal/* route requires a valid X-API-Key -- never public (issue #15).
router = APIRouter(prefix="/internal", tags=["internal"], dependencies=[Depends(verify_internal_api_key)])


@router.get("/ping")
async def ping(caller_service: str = Depends(verify_internal_api_key)):
    """Reachability check for service-to-service calls. Requires X-API-Key."""
    return {"status": "ok", "caller_service": caller_service}


class ProvisionUserRequest(BaseModel):
    email: EmailStr


class ProvisionUserResponse(BaseModel):
    userId: str
    isNewUser: bool


@router.post("/users/provision", response_model=ProvisionUserResponse)
async def provision_user(
    data: ProvisionUserRequest,
    caller_service: str = Depends(verify_internal_api_key),
):
    """Look up or create a userId for guest-checkout flows (e.g. TicketService).

    Returns the existing userId if the email is already registered, otherwise
    creates a CONSUMER account with no usable password and sends the existing
    password-setting email. Never returns a password hash or token.
    """
    existing = await User.find_one(User.email == data.email)
    if existing:
        return ProvisionUserResponse(userId=existing.id, isNewUser=False)

    user = User(
        id=await generate_unique_id(User),
        email=data.email,
        # Random, never returned -- the user sets a real password via the reset link below.
        hashed_password=get_password_hash(create_token(32)),
        is_password_verify=False,
        is_email_verify=False,
        password_reset_token=create_token(32),
        roles=["CONSUMER"],
    )
    try:
        await user.insert()
    except DuplicateKeyError:
        # Lost a race against a concurrent provisioning call for the same email --
        # the unique index on User.email guarantees only one of us created it.
        existing = await User.find_one(User.email == data.email)
        if existing:
            return ProvisionUserResponse(userId=existing.id, isNewUser=False)
        raise

    logger.info(f"Provisioned guest-checkout user {user.id} for caller {caller_service}")
    await send_password_reset_email(user.email, user.password_reset_token, user.id)

    return ProvisionUserResponse(userId=user.id, isNewUser=True)
