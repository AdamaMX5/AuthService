# admin_router.py
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlmodel import select, update
from sqlmodel.ext.asyncio.session import AsyncSession
from database import get_db
from models import User
from auth import get_current_user
import secrets
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


class OneRole(BaseModel):
    user_id: str
    role: str


class RoleList(BaseModel):
    user_id: str
    roles: list[str]


@router.post("/set_roles", status_code=status.HTTP_200_OK)
async def set_roles(data: RoleList, db: AsyncSession = Depends(get_db)):
    """
    Sets the roles of a user to the provided list.
    """
    user = await db.scalar(select(User).where(User.id == data.user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.deleted_at:
        raise HTTPException(status_code=status.HTTP_451_UNAVAILABLE_FOR_LEGAL_REASONS, detail="User is deleted")

    user.roles = data.roles
    await db.commit()
    await db.refresh(user)
    return {"status": "roles_set", "user_id": user.id, "roles": data.roles}