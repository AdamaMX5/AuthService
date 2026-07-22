import asyncio

import pytest
from fastapi import status

from models import User
from test_utils import assert_status_code

API_KEY_HEADER = {"X-API-Key": "ticket-secret-123"}


@pytest.fixture(autouse=True)
def internal_api_key(monkeypatch):
    monkeypatch.setenv("INTERNAL_API_KEY_TICKET_SERVICE", "ticket-secret-123")
    yield


@pytest.mark.asyncio
async def test_provision_requires_api_key(test_client, test_db):
    response = await test_client.post("/internal/users/provision", json={"email": "guest@example.com"})

    assert_status_code(response, status.HTTP_401_UNAUTHORIZED)


@pytest.mark.asyncio
async def test_provision_creates_new_consumer_user(test_client, test_db):
    response = await test_client.post(
        "/internal/users/provision",
        json={"email": "guest@example.com"},
        headers=API_KEY_HEADER,
    )

    assert_status_code(response, status.HTTP_200_OK)
    body = response.json()
    assert body["isNewUser"] is True
    assert body["userId"]
    assert set(body.keys()) == {"userId", "isNewUser"}

    user = await User.get(body["userId"])
    assert user is not None
    assert user.email == "guest@example.com"
    assert user.roles == ["CONSUMER"]
    assert user.is_email_verify is False
    assert user.is_password_verify is False
    assert user.password_reset_token is not None
    assert user.hashed_password != ""


@pytest.mark.asyncio
async def test_provision_returns_existing_user_without_duplicating(test_client, test_db):
    existing = User(id="u_existing1", email="known@example.com", roles=["USER"])
    await existing.insert()

    response = await test_client.post(
        "/internal/users/provision",
        json={"email": "known@example.com"},
        headers=API_KEY_HEADER,
    )

    assert_status_code(response, status.HTTP_200_OK)
    body = response.json()
    assert body == {"userId": "u_existing1", "isNewUser": False}

    count = await User.find(User.email == "known@example.com").count()
    assert count == 1


@pytest.mark.asyncio
async def test_provision_response_never_leaks_password_or_token(test_client, test_db):
    response = await test_client.post(
        "/internal/users/provision",
        json={"email": "secretcheck@example.com"},
        headers=API_KEY_HEADER,
    )

    assert_status_code(response, status.HTTP_200_OK)
    body_text = response.text
    assert "password" not in body_text.lower()
    assert "token" not in body_text.lower()


@pytest.mark.asyncio
async def test_provision_concurrent_same_email_creates_only_one_user(test_client, test_db):
    """Two simultaneous guest checkouts with the same email must not create two accounts."""
    responses = await asyncio.gather(
        test_client.post(
            "/internal/users/provision",
            json={"email": "race@example.com"},
            headers=API_KEY_HEADER,
        ),
        test_client.post(
            "/internal/users/provision",
            json={"email": "race@example.com"},
            headers=API_KEY_HEADER,
        ),
    )

    for response in responses:
        assert_status_code(response, status.HTTP_200_OK)

    user_ids = {response.json()["userId"] for response in responses}
    assert len(user_ids) == 1

    count = await User.find(User.email == "race@example.com").count()
    assert count == 1


@pytest.mark.asyncio
async def test_provision_rejects_invalid_email(test_client, test_db):
    response = await test_client.post(
        "/internal/users/provision",
        json={"email": "not-an-email"},
        headers=API_KEY_HEADER,
    )

    assert_status_code(response, status.HTTP_422_UNPROCESSABLE_ENTITY)
