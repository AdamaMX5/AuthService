# test/conftest.py
import sys
import logging
from pathlib import Path

import pytest
from httpx import AsyncClient
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    async_sessionmaker,
)
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel


root_dir = Path(__file__).parent.parent
sys.path.insert(0, str(root_dir))

from main import app
from database import get_db
import auth

# -------------------------------------------------
# Logging
# -------------------------------------------------
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
logging.getLogger("sqlalchemy.pool").setLevel(logging.WARNING)
logging.getLogger("sqlalchemy.dialects").setLevel(logging.WARNING)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# -------------------------------------------------
# FastAPI Validation Error Handler
# -------------------------------------------------
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
async def test_engine():
    """
    Each test gets his own engine + new SQLite In-Memory DB.
    -> no Statement-Cache
    -> no Ghost-User
    """
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        echo=False,
        future=True,
        poolclass=StaticPool,
    )

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)

    await engine.dispose()


@pytest.fixture(scope="function")
async def test_db(test_engine):
    """
    Each test a new AsyncSession.
    """
    async_session = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session() as session:
        yield session


@pytest.fixture(scope="function")
async def override_get_db(test_db):
    """
    Dependency Override für FastAPI Router.
    """
    async def _get_db():
        yield test_db

    return _get_db


@pytest.fixture(scope="function")
async def test_client(override_get_db):
    """
    TestClient with Dependency Override.
    """
    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        app=app,
        base_url="http://test",
    ) as client:
        yield client

    app.dependency_overrides.clear()


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
