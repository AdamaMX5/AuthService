import pytest
from fastapi import HTTPException, status

import auth


def test_create_access_token_without_rs_private_key_returns_503():
    auth.ALGORITHM = "RS256"
    auth.JWT_PRIVATE_KEY = None

    with pytest.raises(HTTPException) as exc:
        auth.create_access_token({"sub": "user@example.com"})

    assert exc.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
