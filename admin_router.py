# admin_router.py
from datetime import datetime
from typing import Any

import json

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field

from auth import configure_jwt_keys, get_current_user, get_jwt_key_storage_info
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


class UserImportItem(BaseModel):
    id: str
    email: str
    email_verify: bool = False
    hashed_password: str
    hash_scheme: str | None = None
    password_verify: bool = False
    last_login: datetime | None = None
    roles: list[str] = Field(default_factory=lambda: ["USER"])
    comment: str = ""
    deleted_at: datetime | None = None


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


async def _get_active_user_or_404(user_id: str) -> User:
    user = await User.get(user_id)
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
    current_user: User = Depends(get_current_user),
):
    """Sets the roles of a user to the provided list."""
    _require_admin(current_user)

    user = await _get_active_user_or_404(data.user_id)
    user.roles = data.roles

    await user.replace()
    return {"status": "roles_set", "user_id": user.id, "roles": data.roles}


@router.post("/set_permissions", status_code=status.HTTP_200_OK)
async def set_permissions(
    data: PermissionDict,
    current_user: User = Depends(get_current_user),
):
    """Replace all permissions for a user."""
    _require_admin(current_user)

    user = await _get_active_user_or_404(data.user_id)
    user.permissions = data.permissions

    await user.replace()
    return {
        "status": "permissions_set",
        "user_id": user.id,
        "permissions": user.permissions,
    }


@router.post("/upsert_permission", status_code=status.HTTP_200_OK)
async def upsert_permission(
    data: PermissionItem,
    current_user: User = Depends(get_current_user),
):
    """Create or update one permission key."""
    _require_admin(current_user)

    user = await _get_active_user_or_404(data.user_id)
    permissions = dict(user.permissions or {})
    permissions[data.key] = data.value
    user.permissions = permissions

    await user.replace()
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
    current_user: User = Depends(get_current_user),
):
    """Remove one permission key if present."""
    _require_admin(current_user)

    user = await _get_active_user_or_404(data.user_id)
    permissions = dict(user.permissions or {})

    if data.key not in permissions:
        raise HTTPException(status_code=404, detail="Permission key not found")

    removed_value = permissions.pop(data.key)
    user.permissions = permissions

    await user.replace()
    return {
        "status": "permission_removed",
        "user_id": user.id,
        "key": data.key,
        "removed_value": removed_value,
        "permissions": user.permissions,
    }


@router.get("/users", status_code=status.HTTP_200_OK)
async def list_users(
    current_user: User = Depends(get_current_user),
):
    """Return all users with their full persisted data."""
    _require_admin(current_user)

    users = await User.find_all().to_list()
    return {"status": "users_listed", "users": [_serialize_user(user) for user in users]}


@router.get("/users/{user_id}", status_code=status.HTTP_200_OK)
async def get_user(
    user_id: str,
    current_user: User = Depends(get_current_user),
):
    """Return one user with full persisted data."""
    _require_admin(current_user)

    user = await User.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {"status": "user_loaded", "user": _serialize_user(user)}


@router.patch("/users/{user_id}", status_code=status.HTTP_200_OK)
async def patch_user(
    user_id: str,
    payload: UserPatch,
    current_user: User = Depends(get_current_user),
):
    """Update one or multiple user fields in one request."""
    _require_admin(current_user)

    user = await User.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields provided for update")

    for key, value in updates.items():
        setattr(user, key, value)

    await user.replace()
    return {"status": "user_updated", "updated_fields": list(updates.keys()), "user": _serialize_user(user)}


@router.post("/users/import", status_code=status.HTTP_200_OK)
async def import_users(
    file: UploadFile,
    current_user: User = Depends(get_current_user),
):
    """Import users from a JSON file and upsert by id (with email match for updates)."""
    _require_admin(current_user)

    if file.content_type not in {"application/json", "text/json", "application/octet-stream"}:
        raise HTTPException(status_code=400, detail="Only JSON files are supported")

    try:
        raw = await file.read()
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON file: {exc.msg}") from exc

    if not isinstance(payload, list):
        raise HTTPException(status_code=400, detail="JSON root must be a list of users")

    created = 0
    updated = 0
    skipped = 0
    skipped_reasons: list[dict[str, str]] = []

    for idx, item in enumerate(payload, start=1):
        try:
            import_user = UserImportItem.model_validate(item)
        except Exception as exc:
            skipped += 1
            skipped_reasons.append({"index": str(idx), "reason": f"invalid payload: {exc}"})
            continue

        existing_user = await User.get(import_user.id)

        if existing_user:
            if existing_user.email != import_user.email:
                skipped += 1
                skipped_reasons.append(
                    {
                        "id": import_user.id,
                        "reason": "id already exists with a different email",
                    }
                )
                continue

            existing_user.is_email_verify = import_user.email_verify
            existing_user.hashed_password = import_user.hashed_password
            existing_user.is_password_verify = import_user.password_verify
            existing_user.last_login = import_user.last_login
            existing_user.roles = import_user.roles
            existing_user.comment = import_user.comment
            existing_user.deleted_at = import_user.deleted_at
            await existing_user.replace()
            updated += 1
            continue

        existing_by_email = await User.find_one(User.email == import_user.email)
        if existing_by_email:
            skipped += 1
            skipped_reasons.append(
                {
                    "id": import_user.id,
                    "reason": "email already exists on another user id",
                }
            )
            continue

        await User(
            id=import_user.id,
            email=import_user.email,
            is_email_verify=import_user.email_verify,
            hashed_password=import_user.hashed_password,
            is_password_verify=import_user.password_verify,
            roles=import_user.roles,
            comment=import_user.comment,
            deleted_at=import_user.deleted_at,
            last_login=import_user.last_login,
        ).insert()
        created += 1

    return {
        "status": "users_imported",
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "skipped_reasons": skipped_reasons,
    }


_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


@router.get("/logs", status_code=status.HTTP_200_OK)
async def get_logs(
    current_user: User = Depends(get_current_user),
    minutes: float = Query(
        default=5.0,
        ge=0.1,
        le=1440,
        description="Time window in minutes (0.1–1440, i.e. up to 24 h)",
    ),
    level: str | None = Query(
        default=None,
        description="Minimum log level to include: DEBUG | INFO | WARNING | ERROR | CRITICAL",
    ),
    limit: int = Query(default=200, ge=1, le=1000, description="Max entries per page"),
    offset: int = Query(default=0, ge=0, description="Entries to skip (pagination)"),
):
    """Return recent log entries from the in-memory ring buffer.

    Entries are ordered oldest-first. The ring buffer holds the last 2 000
    records across all log levels that reached the root logger (INFO+ by
    default). Each entry carries an optional ``request_id`` correlation ID
    injected by the RequestIDMiddleware.
    """
    _require_admin(current_user)

    if level is not None and level.upper() not in _VALID_LOG_LEVELS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid log level '{level}'. Use one of: {', '.join(sorted(_VALID_LOG_LEVELS))}",
        )

    from log_buffer import query_logs

    logs, total = query_logs(
        minutes=minutes,
        min_level=level,
        limit=limit,
        offset=offset,
    )

    return {
        "status": "ok",
        "total": total,
        "returned": len(logs),
        "query": {
            "minutes": minutes,
            "level": level,
            "limit": limit,
            "offset": offset,
        },
        "logs": logs,
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
