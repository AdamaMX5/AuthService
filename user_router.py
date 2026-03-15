# user_router.py
import limiter
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request, Cookie
from datetime import datetime, timedelta
from typing import Optional, List
from pydantic import BaseModel, EmailStr, validator

from lib.emailApi import send_verification_email, send_password_reset_email
from models import User, Device, RefreshToken, generate_unique_id
from auth import get_password_hash, verify_password, create_access_token, create_token, hash_token, \
    get_current_user, build_access_token_payload
import secrets
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/user", tags=["user"])


class UserLogin(BaseModel):
    email: EmailStr
    password: str
    device_fingerprint: Optional[str] = None
    device_name: Optional[str] = None


class UserLoginResponse(BaseModel):
    id: str
    email: EmailStr
    access_token: str
    status: str
    roles: List[str]
    last_login: datetime | None = None


class UserRegister(BaseModel):
    email: EmailStr
    repassword: str
    device_fingerprint: Optional[str] = None
    device_name: Optional[str] = None


@router.post("/login")
@limiter.limit(rate=5)
async def login(
        data: UserLogin,
        request: Request,
        response: Response,
):
    """
    Login user or start register process and return access/refresh tokens.
    """
    logger.info(f"find User with email: {data.email} and Device-Fingerprint: {data.device_fingerprint}")
    logger.info(f"Login attempt for email: {data.email}")
    logger.debug(f"Received data: {data}")
    logger.debug(f"Password present: {bool(data.password)}")

    if not hasattr(data, 'password') or not data.password:
        logger.error("No password provided in request")
        raise HTTPException(
            status_code=422,
            detail="Password field is missing or empty"
        )

    user = await User.find_one(User.email == data.email)
    if not user:
        # Registration process started: new User-Object:
        new_user = User(
            id=await generate_unique_id(User),
            email=data.email,
            last_login=datetime.utcnow(),
            hashed_password=get_password_hash(data.password),
            is_password_verify=False,
            is_email_verify=False,
        )
        await new_user.insert()

        logger.warning(f"New User created and registration process is started: {new_user}")
        return UserLoginResponse(
            id=new_user.id,
            email=new_user.email,
            roles=[],
            access_token="",
            status="register"
        )

    if user.deleted_at:
        raise HTTPException(status_code=status.HTTP_451_UNAVAILABLE_FOR_LEGAL_REASONS, detail="User is deleted call support")

    if not user.is_password_verify:
        logger.warning(f"User found but not registered, start registration process again: {user}")
        return UserLoginResponse(
            id=user.id,
            email=user.email,
            roles=[],
            access_token="",
            status="register",
        )
    return await login_user(
        user=user,
        password=data.password,
        request=request,
        response=response,
        device_fingerprint=data.device_fingerprint,
        device_name=data.device_name,
    )


async def login_user(
    *,
    user: User,
    password: str,
    request: Request,
    response: Response,
    device_fingerprint: str | None = None,
    device_name: str | None = None,
) -> UserLoginResponse:

    if not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid password")

    last_login = user.last_login
    user.last_login = datetime.utcnow()
    if not user.is_email_verify:
        user.email_verify_token = create_token(32)
        await send_verification_email(user.email, user.email_verify_token, user.id)
        status_msg = "login_with_verify_email_send"
    else:
        status_msg = "login"

    # Device Handling
    user_agent = request.headers.get("user-agent", "unknown")
    ip_address = request.client.host if request.client else "unknown"
    logger.warning(f"device_fingerprint in login_user() = {device_fingerprint!r}. Request.Headers: {request.headers}, IP-Adress: {ip_address}")
    device = None
    if device_fingerprint:
        device = await Device.find_one(
            Device.fingerprint == device_fingerprint,
            Device.user_id == user.id,
        )
    if not device:
        device = Device(
            id=await generate_unique_id(Device),
            user_id=user.id,
            fingerprint=device_fingerprint or create_token(32),
            name=device_name or "Unknown Device",
            type="browser",
            platform=request.headers.get("sec-ch-ua-platform", "unknown"),
            browser=user_agent,
            os="unknown",
            ip=ip_address,
            trusted=True,
            first_use=datetime.utcnow(),
            last_use=datetime.utcnow(),
        )
        await device.insert()
    else:
        device.last_use = datetime.utcnow()
        await device.replace()
    logger.warning(f"Device for user {user.email}: {device}")

    # Refresh Token Handling (Opaque Token),
    # random Chars/String, no Claims, no JWT, only hash in DB, revocation possible, token rotation,
    # Expires after 7-14 days (stored in DB), HttpOnly-Cookie
    refresh_token = create_token(64)
    refresh_token_hash = hash_token(refresh_token)
    refresh_token_db = RefreshToken(
        id=await generate_unique_id(RefreshToken),
        device_id=device.id,
        token_hash=refresh_token_hash,
        issued_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=7),
        revoked=False,
    )
    await refresh_token_db.insert()
    await user.replace()
    logger.info(f"User {user.email} logged in successfully. last login old was {last_login}, actual last_login is {user.last_login}")

    # HttpOnly-Cookie for Refresh Token (Browser stores it automatically, JavaScript do not see it -> more Secure)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=60 * 60 * 24 * 14,
        path="/user/refresh",
    )
    return UserLoginResponse(
        id=user.id,
        email=user.email,
        roles=user.roles,
        access_token=create_access_token(data=build_access_token_payload(
            email=user.email,
            roles=user.roles,
            permissions=user.permissions,
        )),
        status=status_msg,
        last_login=last_login,
    )


@router.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit(rate=3)
async def register_user(data: UserRegister, request: Request, response: Response):
    user = await User.find_one(User.email == data.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_password_verify:
        raise HTTPException(status_code=400, detail="User is already registered")
    if not verify_password(data.repassword, user.hashed_password):
        await user.delete()
        raise HTTPException(status_code=400, detail="Second Password is incorrect, please try registration again.")

    user.is_password_verify = True
    user.is_email_verify = False
    user.email_verify_token = create_token(32)
    user.last_login = datetime.utcnow()

    roles = list(user.roles or [])
    if "USER" not in roles:
        roles.append("USER")
        logger.info("Assigning USER role to newly registered user, after checking repassword is correct")

    # give Admin-role when no user is Admin
    admin_exists = await User.find_one({"deleted_at": None, "roles": "ADMIN"})
    logger.info(f"Admin already exists check during registration of a user: {admin_exists}")

    if not admin_exists:
        logger.warning("No Admin detected - assigning ADMIN role")
        roles.append("ADMIN")
    user.roles = roles

    await user.replace()

    return await login_user(
        user=user,
        password=data.repassword,
        request=request,
        response=response,
        device_fingerprint=data.device_fingerprint,
        device_name=data.device_name,
    )


@router.get("/verify-email")
async def verify_email(token: str, user_id: str):
    user = await User.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_email_verify:
        return {"status": "email_already_verified"}
    if user.email_verify_token != token:
        raise HTTPException(status_code=400, detail="Invalid verification token")

    user.is_email_verify = True
    user.email_verify_token = None
    user.edited(editor=user.email, comment="Email verified")
    await user.replace()
    return {"status": "email_verified"}


@router.post("/reset-password")
@limiter.limit(rate=3)
async def reset_password(token: str, user_id: str, new_password: str, repassword: str):
    user = await User.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.password_reset_token != token:
        raise HTTPException(status_code=400, detail="Invalid password reset token")
    if new_password != repassword:
        raise HTTPException(status_code=400, detail="Passwords do not match, please try again.")

    user.hashed_password = get_password_hash(new_password)
    user.password_reset_token = None
    await user.replace()
    return {"status": "password_reset"}


@router.post("/refresh")
@limiter.limit(rate=5)
async def refresh(
    response: Response,
    refresh_token: str | None = Cookie(default=None),
):
    logger.info(f"Refreshing access token using refresh token from cookie: {refresh_token}")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    token_hash = hash_token(refresh_token)
    logger.info(f"Computed hash of refresh token: {token_hash} = hash_token({refresh_token})")
    # load refresh token
    db_token = await RefreshToken.find_one(RefreshToken.token_hash == token_hash)
    if not db_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if db_token.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Refresh token expired")
    if db_token.revoked:
        # TODO: Token is used double, maybe an attack? Revoke all tokens for this device?
        raise HTTPException(status_code=401, detail="Refresh token revoked")

    # load device
    device = await Device.get(db_token.device_id)
    if not device:
        raise HTTPException(status_code=401, detail="Device not found")

    device_owner = await User.get(device.user_id)
    if not device_owner:
        raise HTTPException(status_code=401, detail="User not found")

    device.last_use = datetime.utcnow()
    await device.replace()

    # Token Rotation
    new_refresh_token = create_token(64)
    new_refresh_hash = hash_token(new_refresh_token)

    new_db_token = RefreshToken(
        id=await generate_unique_id(RefreshToken),
        device_id=device.id,
        token_hash=new_refresh_hash,
        issued_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=7),
        revoked=False,
        rotated_from=db_token.id,
    )
    # lock old Token
    db_token.revoked = True
    await db_token.replace()
    await new_db_token.insert()

    # save new RefreshToken in Cookie
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=60 * 60 * 24 * 7,
        path="/user/refresh",
    )
    return {
        "access_token": create_access_token(data=build_access_token_payload(
            email=device_owner.email,
            roles=device_owner.roles,
            permissions=device_owner.permissions,
        ))
    }


@router.post("/password-reset-request")
@limiter.limit(rate=1)
async def password_reset_request(email: EmailStr):
    user = await User.find_one(User.email == email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.password_reset_token = create_token(32)
    await user.replace()
    await send_password_reset_email(
        user.email,
        user.password_reset_token,
        user.id,
    )


@router.post("/logout")
async def logout(
    response: Response,
    refresh_token: str | None = Cookie(default=None),
):
    if refresh_token:
        token_hash = hash_token(refresh_token)
        db_token = await RefreshToken.find_one(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == False,
        )
        if db_token:
            db_token.revoked = True
            await db_token.replace()

    # delete Cookie
    response.delete_cookie(
        key="refresh_token",
        path="/auth/refresh",
    )
    return {"status": "logged_out"}


@router.post("/logout-all")
async def logout_all(
    response: Response,
    user: User = Depends(get_current_user),
):
    devices = await Device.find(Device.user_id == user.id).to_list()
    device_ids = [d.id for d in devices]

    if device_ids:
        await RefreshToken.get_motor_collection().update_many(
            {"device_id": {"$in": device_ids}},
            {"$set": {"revoked": True}},
        )

    response.delete_cookie(
        key="refresh_token",
        path="/auth/refresh",
    )

    return {"status": "logged_out_all"}
