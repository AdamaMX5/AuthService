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
async def test_correct_email_requires_api_key(test_client, test_db):
    guest = User(id="u_guest1", email="typo@example.com", roles=["CONSUMER"], is_email_verify=False)
    await guest.insert()

    response = await test_client.patch(
        f"/internal/users/{guest.id}/email",
        json={"newEmail": "fixed@example.com"},
    )

    assert_status_code(response, status.HTTP_401_UNAUTHORIZED)


@pytest.mark.asyncio
async def test_correct_email_updates_unverified_account(test_client, test_db):
    guest = User(
        id="u_guest2",
        email="typo2@example.com",
        roles=["CONSUMER"],
        is_email_verify=False,
        is_password_verify=False,
        password_reset_token="old-token",
    )
    await guest.insert()

    response = await test_client.patch(
        f"/internal/users/{guest.id}/email",
        json={"newEmail": "fixed2@example.com"},
        headers=API_KEY_HEADER,
    )

    assert_status_code(response, status.HTTP_200_OK)
    assert response.json() == {"userId": "u_guest2", "email": "fixed2@example.com", "isEmailVerified": False}

    updated = await User.get("u_guest2")
    assert updated.email == "fixed2@example.com"
    assert updated.password_reset_token != "old-token"


@pytest.mark.asyncio
async def test_correct_email_resends_verify_email_when_password_already_set(test_client, test_db):
    """If the account already has a real password, re-triggering the password-setting
    mail would be wrong -- the existing verify-email flow must be used instead."""
    user = User(
        id="u_guest3",
        email="typo3@example.com",
        roles=["CONSUMER"],
        is_email_verify=False,
        is_password_verify=True,
        email_verify_token="old-verify-token",
    )
    await user.insert()

    response = await test_client.patch(
        f"/internal/users/{user.id}/email",
        json={"newEmail": "fixed3@example.com"},
        headers=API_KEY_HEADER,
    )

    assert_status_code(response, status.HTTP_200_OK)
    updated = await User.get("u_guest3")
    assert updated.email == "fixed3@example.com"
    assert updated.email_verify_token != "old-verify-token"


@pytest.mark.asyncio
async def test_correct_email_rejects_already_verified_account(test_client, test_db):
    """Hard server-side lock: a verified/claimed account must never be reachable
    through this endpoint, regardless of what the caller believes it validated."""
    verified_user = User(id="u_verified1", email="real@example.com", roles=["CONSUMER"], is_email_verify=True)
    await verified_user.insert()

    response = await test_client.patch(
        f"/internal/users/{verified_user.id}/email",
        json={"newEmail": "attacker-controlled@example.com"},
        headers=API_KEY_HEADER,
    )

    assert_status_code(response, status.HTTP_403_FORBIDDEN)
    unchanged = await User.get("u_verified1")
    assert unchanged.email == "real@example.com"


@pytest.mark.asyncio
async def test_correct_email_rejects_non_consumer_account(test_client, test_db):
    """is_email_verify alone is not a safe boundary -- an unverified ADMIN/GITCLIENT
    account must not be reachable through this guest-checkout-typo-fix endpoint."""
    admin = User(id="u_admin_unverified1", email="admin@example.com", roles=["ADMIN"], is_email_verify=False)
    await admin.insert()

    response = await test_client.patch(
        f"/internal/users/{admin.id}/email",
        json={"newEmail": "attacker-controlled@example.com"},
        headers=API_KEY_HEADER,
    )

    assert_status_code(response, status.HTTP_403_FORBIDDEN)
    unchanged = await User.get("u_admin_unverified1")
    assert unchanged.email == "admin@example.com"


@pytest.mark.asyncio
async def test_correct_email_rejects_email_already_used_by_another_account(test_client, test_db):
    guest = User(id="u_guest4", email="typo4@example.com", roles=["CONSUMER"], is_email_verify=False)
    other = User(id="u_other1", email="taken@example.com", roles=["USER"], is_email_verify=True)
    await guest.insert()
    await other.insert()

    response = await test_client.patch(
        f"/internal/users/{guest.id}/email",
        json={"newEmail": "taken@example.com"},
        headers=API_KEY_HEADER,
    )

    assert_status_code(response, status.HTTP_409_CONFLICT)
    unchanged = await User.get("u_guest4")
    assert unchanged.email == "typo4@example.com"


@pytest.mark.asyncio
async def test_correct_email_allows_setting_same_email_as_self(test_client, test_db):
    """The uniqueness check must exclude the account being updated itself."""
    guest = User(id="u_guest5", email="same@example.com", roles=["CONSUMER"], is_email_verify=False)
    await guest.insert()

    response = await test_client.patch(
        f"/internal/users/{guest.id}/email",
        json={"newEmail": "same@example.com"},
        headers=API_KEY_HEADER,
    )

    assert_status_code(response, status.HTTP_200_OK)


@pytest.mark.asyncio
async def test_correct_email_unknown_user_returns_404(test_client, test_db):
    response = await test_client.patch(
        "/internal/users/u_does_not_exist/email",
        json={"newEmail": "fixed@example.com"},
        headers=API_KEY_HEADER,
    )

    assert_status_code(response, status.HTTP_404_NOT_FOUND)


@pytest.mark.asyncio
async def test_correct_email_rejects_invalid_email(test_client, test_db):
    guest = User(id="u_guest6", email="typo6@example.com", roles=["CONSUMER"], is_email_verify=False)
    await guest.insert()

    response = await test_client.patch(
        f"/internal/users/{guest.id}/email",
        json={"newEmail": "not-an-email"},
        headers=API_KEY_HEADER,
    )

    assert_status_code(response, status.HTTP_422_UNPROCESSABLE_ENTITY)
