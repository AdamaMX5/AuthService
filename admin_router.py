# admin_router.py
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from auth import get_current_user
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
