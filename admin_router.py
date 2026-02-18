# admin_router.py
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
