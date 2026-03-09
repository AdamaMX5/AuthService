import pytest

import main
import auth


@pytest.mark.asyncio
async def test_get_jwt_public_key_not_configured():
    auth.JWT_PUBLIC_KEY = None

    response = await main.get_jwt_public_key()

    assert response["status"] == "not_configured"
    assert response["public_key"] is None


@pytest.mark.asyncio
async def test_get_jwt_public_key_strips_newlines():
    auth.JWT_PRIVATE_KEY = "private"
    auth.JWT_PUBLIC_KEY = "line-1\nline-2\n"
    auth.ALGORITHM = "RS256"

    response = await main.get_jwt_public_key()

    assert response["status"] == "ok"
    assert response["algorithm"] == "RS256"
    assert response["public_key"] == "line-1line-2"
