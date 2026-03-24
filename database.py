# database.py
import os
from dotenv import load_dotenv

load_dotenv()

from urllib.parse import urlparse as _urlparse

_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017/authservice")
MONGODB_URL = _uri
MONGODB_DB_NAME = _urlparse(_uri).path.lstrip("/") or "authservice"

_client = None


async def init_db():
    """Initialize MongoDB connection and Beanie ODM."""
    global _client
    from motor.motor_asyncio import AsyncIOMotorClient
    from beanie import init_beanie
    from models import User, Device, RefreshToken
    try:
        _client = AsyncIOMotorClient(MONGODB_URL)
        await init_beanie(
            database=_client[MONGODB_DB_NAME],
            document_models=[User, Device, RefreshToken],
        )
        print("✅ MongoDB connected and Beanie initialized!")
        return True
    except Exception as e:
        print(f"❌ Failed to connect to MongoDB: {e}")
        return False


async def get_db():
    """Dependency placeholder - Beanie manages the connection globally."""
    yield
