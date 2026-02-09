import asyncio
from datetime import datetime, timedelta

from pydantic import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from models import User, Device, RefreshToken
from auth import get_password_hash, create_token, hash_token


def make_user(**overrides):
    return User(
        id=overrides.get("id", "user_id"),
        email=overrides.get("email", "user@example.com"),
        hashed_password=overrides.get("hashed_password", get_password_hash(overrides.get("password", "Test123!"))),
        password_reset_token=overrides.get("password_reset_token", None),
        is_password_verify=overrides.get("is_password_verify", True),
        is_email_verify=overrides.get("is_email_verify", True),
        email_verify_token=overrides.get("email_verify_token", None),
        roles=overrides.get("roles", ["USER"]),
        last_login=overrides.get("last_login", datetime.utcnow() - timedelta(days=1)),
    )


def make_device(**overrides):
    return Device(
        id=overrides.get("id", "device_id"),
        user_id=overrides.get("user_id", "user_id"),
        fingerprint=overrides.get("fingerprint", "test_fingerprint"),
        last_use=overrides.get("last_use", datetime.utcnow() - timedelta(hours=1)),
    )


def make_refresh_token(**overrides):
    refresh_token = overrides.get("refresh_token", "test_refresh_token")
    return RefreshToken(
        id=overrides.get("id", "refresh_token_id"),
        device_id=overrides.get("device_id", "device_id"),
        token_hash=overrides.get("token_hash", hash_token(refresh_token)),
        expires_at=overrides.get("expires_at", datetime.utcnow() + timedelta(days=7)),
        revoked=overrides.get("revoked", False),
    )



def get_auth_headers(access_token: str) -> dict:
    return {"Authorization": f"Bearer {access_token}"}


def assert_status_code(response, expected_code, message=""):
    if response.status_code != expected_code:
        detail = "No detail"
        try:
            data = response.json()
            detail = data.get('detail', str(data))
        except (ValueError, json.JSONDecodeError):
            detail = response.text or "No JSON response"

        raise AssertionError(
            f"Expected status code {expected_code} but got {response.status_code}. "
            f"Detail: {detail}. "
            f"{message}"
        )
