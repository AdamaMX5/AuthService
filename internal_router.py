# internal_router.py
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from pymongo.errors import DuplicateKeyError

from auth import create_token, get_password_hash, verify_internal_api_key
from lib.emailApi import send_password_reset_email, send_verification_email
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


class CorrectEmailRequest(BaseModel):
    newEmail: EmailStr


class CorrectEmailResponse(BaseModel):
    userId: str
    email: EmailStr
    isEmailVerified: bool


@router.patch("/users/{user_id}/email", response_model=CorrectEmailResponse)
async def correct_email(
    user_id: str,
    data: CorrectEmailRequest,
    caller_service: str = Depends(verify_internal_api_key),
):
    """Correct a mistyped email for a not-yet-verified account (e.g. guest checkout typo).

    The caller is trusted to have already validated its own short-lived, purchase-bound
    claim token -- AuthService does not know about that token. As defense-in-depth,
    AuthService independently enforces that this can only ever touch accounts where
    is_email_verify is still False, so an already-claimed/verified account can never
    have its email hijacked through this path, regardless of what the caller believes.

    Scoped to CONSUMER-only accounts (guest checkout, see #16): is_email_verify alone
    is not a safe boundary, since any account (including a not-yet-verified ADMIN or
    GITCLIENT one) could otherwise have its email redirected and its password taken
    over via the resulting password-setting link.
    """
    user = await User.get(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if set(user.roles or []) != {"CONSUMER"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email correction is only available for guest-checkout (CONSUMER) accounts",
        )

    if user.is_email_verify:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email is already verified and can no longer be changed via this endpoint",
        )

    other_user = await User.find_one(User.email == data.newEmail)
    if other_user and other_user.id != user.id:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already in use")

    user.email = data.newEmail

    # Re-trigger whichever identity email matches this account's current state,
    # same as the flows used by register-complete (#13) and guest provisioning (#16).
    resend_password_setting_mail = not user.is_password_verify
    if resend_password_setting_mail:
        user.password_reset_token = create_token(32)
    else:
        user.email_verify_token = create_token(32)

    try:
        await user.replace()
    except DuplicateKeyError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already in use")

    logger.info(f"Corrected email for user {user.id} to new address, requested by caller {caller_service}")
    if resend_password_setting_mail:
        await send_password_reset_email(user.email, user.password_reset_token, user.id)
    else:
        await send_verification_email(user.email, user.email_verify_token, user.id)

    return CorrectEmailResponse(userId=user.id, email=user.email, isEmailVerified=user.is_email_verify)
