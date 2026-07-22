import pytest
from fastapi import HTTPException, status

from auth import create_access_token, get_internal_api_keys, verify_internal_api_key
from test_utils import assert_status_code, get_auth_headers


@pytest.fixture(autouse=True)
def clear_internal_api_keys(monkeypatch):
    """Ensure no leftover INTERNAL_API_KEY_* env vars leak between tests."""
    for name in list(get_internal_api_keys().keys()):
        monkeypatch.delenv(f"INTERNAL_API_KEY_{name}", raising=False)
    yield


def test_verify_internal_api_key_accepts_configured_key(monkeypatch):
    monkeypatch.setenv("INTERNAL_API_KEY_TICKET_SERVICE", "ticket-secret-123")

    caller = verify_internal_api_key(x_api_key="ticket-secret-123")

    assert caller == "TICKET_SERVICE"


def test_verify_internal_api_key_rejects_wrong_key(monkeypatch):
    monkeypatch.setenv("INTERNAL_API_KEY_TICKET_SERVICE", "ticket-secret-123")

    with pytest.raises(HTTPException) as exc_info:
        verify_internal_api_key(x_api_key="not-the-right-key")

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_verify_internal_api_key_rejects_missing_header():
    with pytest.raises(HTTPException) as exc_info:
        verify_internal_api_key(x_api_key=None)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_verify_internal_api_key_resolves_correct_service_among_several(monkeypatch):
    monkeypatch.setenv("INTERNAL_API_KEY_TICKET_SERVICE", "ticket-secret-123")
    monkeypatch.setenv("INTERNAL_API_KEY_MARKET_SERVICE", "market-secret-456")

    assert verify_internal_api_key(x_api_key="ticket-secret-123") == "TICKET_SERVICE"
    assert verify_internal_api_key(x_api_key="market-secret-456") == "MARKET_SERVICE"


def test_verify_internal_api_key_ignores_unrelated_env_vars(monkeypatch):
    """Only INTERNAL_API_KEY_* is trusted -- an unrelated *_API_KEY secret must not grant access."""
    monkeypatch.setenv("STRIPE_API_KEY", "sk_live_unrelated_secret")

    with pytest.raises(HTTPException) as exc_info:
        verify_internal_api_key(x_api_key="sk_live_unrelated_secret")

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_internal_ping_rejects_missing_api_key(test_client, test_db, monkeypatch):
    monkeypatch.setenv("INTERNAL_API_KEY_TICKET_SERVICE", "ticket-secret-123")

    response = await test_client.get("/internal/ping")

    assert_status_code(response, status.HTTP_401_UNAUTHORIZED)


@pytest.mark.asyncio
async def test_internal_ping_rejects_invalid_api_key(test_client, test_db, monkeypatch):
    monkeypatch.setenv("INTERNAL_API_KEY_TICKET_SERVICE", "ticket-secret-123")

    response = await test_client.get("/internal/ping", headers={"X-API-Key": "wrong"})

    assert_status_code(response, status.HTTP_401_UNAUTHORIZED)


@pytest.mark.asyncio
async def test_internal_ping_accepts_valid_api_key(test_client, test_db, monkeypatch):
    monkeypatch.setenv("INTERNAL_API_KEY_TICKET_SERVICE", "ticket-secret-123")

    response = await test_client.get("/internal/ping", headers={"X-API-Key": "ticket-secret-123"})

    assert_status_code(response, status.HTTP_200_OK)
    assert response.json() == {"status": "ok", "caller_service": "TICKET_SERVICE"}


@pytest.mark.asyncio
async def test_internal_ping_not_reachable_with_jwt_alone(test_client, test_db, monkeypatch):
    """A valid user JWT must not substitute for the internal API key -- /internal/* is
    exclusively for service-to-service calls (issue #15)."""
    monkeypatch.setenv("INTERNAL_API_KEY_TICKET_SERVICE", "ticket-secret-123")
    token = create_access_token({"sub": "someone@example.com"})

    response = await test_client.get("/internal/ping", headers=get_auth_headers(token))

    assert_status_code(response, status.HTTP_401_UNAUTHORIZED)
