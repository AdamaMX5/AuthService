import pytest
from fastapi import status

from test_utils import assert_status_code


@pytest.mark.asyncio
async def test_get_jwt_public_key_not_configured(test_client):
    response = await test_client.get("/jwt/public-key")

    assert_status_code(response, status.HTTP_200_OK)
    data = response.json()
    assert data["status"] == "not_configured"
    assert data["public_key"] is None
