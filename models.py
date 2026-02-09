# models.py
import random
import string
from datetime import datetime
from sqlmodel import SQLModel, Field, select, Session
from typing import Optional, List, Dict, Any
from sqlalchemy import Column, JSON, event
from typing import Type

from sqlmodel.ext.asyncio.session import AsyncSession


class Base(SQLModel):
    __abstract__ = True
    id: Optional[str] = Field(default=None, primary_key=True, index=True)
    comment: str = Field(default="")
    last_editor: str = Field(default="automatic", title="Email of last staff member who edited")
    created_at: datetime = Field(default_factory=datetime.utcnow, title="Created At")
    edited_at: Optional[datetime] = Field(default=None, nullable=True)
    deleted_at: Optional[datetime] = Field(default=None, nullable=True)

    @classmethod
    def get_prefix(cls) -> str:
        prefix_map = {
            "User": "u",
            "Device": "dvc",
            "RefreshToken": "rt"
        }
        prefix = prefix_map.get(cls.__name__)
        if prefix is None:
            raise ValueError(
                f"No Prefix for Class '{cls.__name__}' defined. "
                f"Please add a prefix to Base Class. "
                f"Available Classes: {list(prefix_map.keys())}"
            )
        return prefix

    def edited(self, editor: str, comment: str = None):
        self.edited_at = datetime.utcnow()
        self.last_editor = editor
        if comment:
            self.comment = comment


class User(Base, table=True):
    __tablename__ = "users"
    email: str = Field(index=True, unique=True, title="email-address", min_length=5)
    email_verify_token: Optional[str] = Field(default=None, title="email-token")
    is_email_verify: bool = Field(default=False, title="email-address is verified")

    hashed_password: str = Field(title="Password-Hash")
    is_password_verify: bool = Field(default=False, title="Password second insert is correct")
    password_reset_token: Optional[str] = Field(default=None, title="Password-token for resetting")

    roles: List[str] = Field(default_factory=lambda: ["USER"], sa_column=Column(JSON))
    permissions: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=True))

    last_login: datetime = Field(default=None, title="Last Login date")


class Device(Base, table=True):
    user_id: Optional[str] = Field(default=None, foreign_key="users.id", title="Owner User ID")
    name: Optional[str] = Field(index=True, title="Device Name", default=None)
    type: Optional[str] = Field(title="Device Type", default=None)
    fingerprint: str = Field(title="Device Fingerprint")
    platform: Optional[str] = Field(title="Device Platform", default=None)
    browser: Optional[str] = Field(title="Device Browser", default=None)
    os: Optional[str] = Field(title="Device Operating System", default=None)
    ip: Optional[str] = Field(title="Device IP Address", default=None)
    trusted: bool = Field(default=True, title="Is Device Trusted")
    first_use: datetime = Field(default_factory=datetime.utcnow, title="First Used At")
    last_use: datetime = Field(default=None, title="Last Used At")


class RefreshToken(Base, table=True):
    device_id: Optional[str] = Field(default=None, foreign_key="device.id", title="Owner Device and UserID")
    token_hash: str = Field(index=True, unique=True, title="Refresh Token")
    issued_at: datetime = Field(default_factory=datetime.utcnow, title="Issued At")
    expires_at: datetime = Field(title="Expires At")
    revoked: bool = Field(default=False, title="Is Token Revoked e.x. logout")
    rotated_from: Optional[str] = Field(default=None, title="Previous Token Hash if Rotated")


async def generate_unique_id(session: AsyncSession, model_class: Type[Base], length: int = 6) -> str:
    """Async uid-generator"""
    candidate_id = random_uid(model_class.get_prefix(), length)
    existing = await session.scalar(select(model_class).where(model_class.id == candidate_id))
    if not existing:
        return candidate_id
    await generate_unique_id(session, model_class, length + 1)


def random_uid(prefix: str, length: int = 6) -> str:
    """Generate random uid with given prefix"""
    characters = string.ascii_letters + string.digits
    random_part = ''.join(random.choice(characters) for _ in range(length))
    return f"{prefix}_{random_part}"
