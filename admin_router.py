# admin_router.py
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from auth import configure_jwt_keys, get_current_user, get_jwt_key_storage_info
from database import get_db
from models import User

router = APIRouter(prefix="/admin", tags=["admin"])


class RoleList(BaseModel):
    user_id: str
    roles: list[str]


class PermissionDict(BaseModel):
    user_id: str
    permissions: dict[str, Any]


class PermissionKey(BaseModel):
    user_id: str
    key: str


class PermissionItem(BaseModel):
    user_id: str
    key: str
    value: Any


class JwtKeyPair(BaseModel):
    private_key: str
    public_key: str
    algorithm: str = "RS256"
    persist_to_files: bool = True

      
class UserPatch(BaseModel):
    email: str | None = None
    email_verify_token: str | None = None
    is_email_verify: bool | None = None
    hashed_password: str | None = None
    is_password_verify: bool | None = None
    password_reset_token: str | None = None
    roles: list[str] | None = None
    permissions: dict[str, Any] | None = None
    comment: str | None = None
    last_editor: str | None = None
    last_login: datetime | None = None


def _serialize_user(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "email": user.email,
        "email_verify_token": user.email_verify_token,
        "is_email_verify": user.is_email_verify,
        "hashed_password": user.hashed_password,
        "is_password_verify": user.is_password_verify,
        "password_reset_token": user.password_reset_token,
        "roles": user.roles,
        "permissions": user.permissions,
        "comment": user.comment,
        "last_editor": user.last_editor,
        "created_at": user.created_at,
        "edited_at": user.edited_at,
        "deleted_at": user.deleted_at,
        "last_login": user.last_login,
    }


def _require_admin(current_user: User) -> None:
    if "ADMIN" not in (current_user.roles or []):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")


async def _get_active_user_or_404(user_id: str, db: AsyncSession) -> User:
    user = await db.scalar(select(User).where(User.id == user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.deleted_at:
        raise HTTPException(
            status_code=status.HTTP_451_UNAVAILABLE_FOR_LEGAL_REASONS,
            detail="User is deleted",
        )
    return user


@router.post("/set_roles", status_code=status.HTTP_200_OK)
async def set_roles(
    data: RoleList,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Sets the roles of a user to the provided list."""
    _require_admin(current_user)

    user = await _get_active_user_or_404(data.user_id, db)
    user.roles = data.roles

    await db.commit()
    await db.refresh(user)
    return {"status": "roles_set", "user_id": user.id, "roles": data.roles}


@router.post("/set_permissions", status_code=status.HTTP_200_OK)
async def set_permissions(
    data: PermissionDict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Replace all permissions for a user."""
    _require_admin(current_user)

    user = await _get_active_user_or_404(data.user_id, db)
    user.permissions = data.permissions

    await db.commit()
    await db.refresh(user)
    return {
        "status": "permissions_set",
        "user_id": user.id,
        "permissions": user.permissions,
    }


@router.post("/upsert_permission", status_code=status.HTTP_200_OK)
async def upsert_permission(
    data: PermissionItem,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create or update one permission key."""
    _require_admin(current_user)

    user = await _get_active_user_or_404(data.user_id, db)
    permissions = dict(user.permissions or {})
    permissions[data.key] = data.value
    user.permissions = permissions

    await db.commit()
    await db.refresh(user)
    return {
        "status": "permission_upserted",
        "user_id": user.id,
        "key": data.key,
        "value": data.value,
        "permissions": user.permissions,
    }


@router.post("/remove_permission", status_code=status.HTTP_200_OK)
async def remove_permission(
    data: PermissionKey,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Remove one permission key if present."""
    _require_admin(current_user)

    user = await _get_active_user_or_404(data.user_id, db)
    permissions = dict(user.permissions or {})

    if data.key not in permissions:
        raise HTTPException(status_code=404, detail="Permission key not found")

    removed_value = permissions.pop(data.key)
    user.permissions = permissions

    await db.commit()
    await db.refresh(user)
    return {
        "status": "permission_removed",
        "user_id": user.id,
        "key": data.key,
        "removed_value": removed_value,
        "permissions": user.permissions,
    }


@router.get("/users", status_code=status.HTTP_200_OK)
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return all users with their full persisted data."""
    _require_admin(current_user)

    users = (await db.exec(select(User))).all()
    return {"status": "users_listed", "users": [_serialize_user(user) for user in users]}


@router.get("/users/{user_id}", status_code=status.HTTP_200_OK)
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return one user with full persisted data."""
    _require_admin(current_user)

    user = await db.scalar(select(User).where(User.id == user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {"status": "user_loaded", "user": _serialize_user(user)}


@router.patch("/users/{user_id}", status_code=status.HTTP_200_OK)
async def patch_user(
    user_id: str,
    payload: UserPatch,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update one or multiple user fields in one request."""
    _require_admin(current_user)

    user = await db.scalar(select(User).where(User.id == user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields provided for update")

    for key, value in updates.items():
        setattr(user, key, value)

    await db.commit()
    await db.refresh(user)
    return {"status": "user_updated", "updated_fields": list(updates.keys()), "user": _serialize_user(user)}
@router.post("/jwt/keys", status_code=status.HTTP_200_OK)
async def set_jwt_keys(
    data: JwtKeyPair,
    current_user: User = Depends(get_current_user),
):
    """Set public/private key pair used for JWT access token signing."""
    _require_admin(current_user)

    configure_jwt_keys(
        private_key=data.private_key,
        public_key=data.public_key,
        algorithm=data.algorithm,
        persist_to_files=data.persist_to_files,
    )

    return {
        "status": "jwt_keys_set",
        "algorithm": data.algorithm,
        "persisted": data.persist_to_files,
        "storage": get_jwt_key_storage_info(),
    }


@router.get("/jwt/key-storage", status_code=status.HTTP_200_OK)
async def get_jwt_key_storage(
    current_user: User = Depends(get_current_user),
):
    """Read key storage configuration and load status."""
    _require_admin(current_user)
    return get_jwt_key_storage_info()
