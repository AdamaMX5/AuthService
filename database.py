# database.py
import os
from dotenv import load_dotenv

load_dotenv()

MONGODB_URL = os.getenv("DATABASE_URL", "mongodb://localhost:27017")
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "authservice")

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
