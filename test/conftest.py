# test/conftest.py
import sys
import logging
from pathlib import Path

import pytest
from httpx import AsyncClient
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

root_dir = Path(__file__).parent.parent
sys.path.insert(0, str(root_dir))

from main import app
import auth

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
):
    body = await request.body()
    logger.warning("Validation error: %s", exc.errors())
    logger.warning("Request body: %s", body.decode())
    return JSONResponse(
        status_code=422,
        content={
            "detail": exc.errors(),
            "body": body.decode(),
        },
    )


@pytest.fixture(scope="function")
async def test_db():
    """
    Each test gets its own in-memory MongoDB mock with fresh Beanie initialization.
    """
    import mongomock_motor
    from beanie import init_beanie
    from models import User, Device, RefreshToken

    client = mongomock_motor.AsyncMongoMockClient()
    await init_beanie(
        database=client["test_db"],
        document_models=[User, Device, RefreshToken],
    )
    yield client

    # Cleanup after each test
    for model in [User, Device, RefreshToken]:
        await model.get_motor_collection().drop()


@pytest.fixture(scope="function")
async def test_client(test_db):
    """
    Test client - test_db must be initialized first (initializes Beanie with mock MongoDB).
    """
    async with AsyncClient(
        app=app,
        base_url="http://test",
    ) as client:
        yield client


@pytest.fixture(autouse=True)
def reset_jwt_config(tmp_path):
    auth.ALGORITHM = "HS256"
    auth.JWT_PRIVATE_KEY = None
    auth.JWT_PUBLIC_KEY = None
    auth.JWT_PRIVATE_KEY_PASSPHRASE = None
    auth.JWT_PRIVATE_KEY_PATH = str(tmp_path / "jwt_private.asc")
    auth.JWT_PUBLIC_KEY_PATH = str(tmp_path / "jwt_public.asc")
    yield
    auth.ALGORITHM = "HS256"
    auth.JWT_PRIVATE_KEY = None
    auth.JWT_PUBLIC_KEY = None
    auth.JWT_PRIVATE_KEY_PASSPHRASE = None
