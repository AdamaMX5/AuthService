# models.py
import random
import string
from datetime import datetime
from typing import Optional, List, Dict, Any, Type

import pymongo
from beanie import Document
from pydantic import Field


class Base(Document):
    id: Optional[str] = None
    comment: str = ""
    last_editor: str = Field(default="automatic", title="Email of last staff member who edited")
    created_at: datetime = Field(default_factory=datetime.utcnow, title="Created At")
    edited_at: Optional[datetime] = None
    deleted_at: Optional[datetime] = None

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

    class Settings:
        use_state_management = True


class User(Base):
    email: str
    email_verify_token: Optional[str] = None
    is_email_verify: bool = False

    hashed_password: str = ""
    is_password_verify: bool = False
    password_reset_token: Optional[str] = None

    roles: List[str] = Field(default_factory=lambda: ["USER"])
    permissions: Dict[str, Any] = Field(default_factory=dict)

    last_login: Optional[datetime] = None

    class Settings:
        name = "users"
        use_state_management = True
        indexes = [
            pymongo.IndexModel([("email", pymongo.ASCENDING)], unique=True),
        ]


class Device(Base):
    user_id: Optional[str] = None
    name: Optional[str] = None
    type: Optional[str] = None
    fingerprint: str = ""
    platform: Optional[str] = None
    browser: Optional[str] = None
    os: Optional[str] = None
    ip: Optional[str] = None
    trusted: bool = True
    first_use: datetime = Field(default_factory=datetime.utcnow, title="First Used At")
    last_use: Optional[datetime] = None

    class Settings:
        name = "devices"
        use_state_management = True


class RefreshToken(Base):
    device_id: Optional[str] = None
    token_hash: str = ""
    issued_at: datetime = Field(default_factory=datetime.utcnow, title="Issued At")
    expires_at: datetime
    revoked: bool = False
    rotated_from: Optional[str] = None

    class Settings:
        name = "refresh_tokens"
        use_state_management = True
        indexes = [
            pymongo.IndexModel([("token_hash", pymongo.ASCENDING)], unique=True),
        ]


async def generate_unique_id(model_class: Type[Base], length: int = 6) -> str:
    """Async uid-generator"""
    candidate_id = random_uid(model_class.get_prefix(), length)
    existing = await model_class.get(candidate_id)
    if not existing:
        return candidate_id
    return await generate_unique_id(model_class, length + 1)


def random_uid(prefix: str, length: int = 6) -> str:
    """Generate random uid with given prefix"""
    characters = string.ascii_letters + string.digits
    random_part = ''.join(random.choice(characters) for _ in range(length))
    return f"{prefix}_{random_part}"
