#main.py
from contextlib import asynccontextmanager

import os

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from user_router import router as UserRouter
from admin_router import router as AdminRouter
from database import init_db
from auth import get_jwt_algorithm, get_public_jwt_key
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _get_cors_settings() -> dict:
    origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
    if not origins:
        logger.warning("CORS_ORIGINS is not set — no origins allowed!")

    methods_raw = os.getenv("CORS_METHODS", "*")
    methods = [m.strip() for m in methods_raw.split(",") if m.strip()]

    headers_raw = os.getenv("CORS_HEADERS", "*")
    headers = [h.strip() for h in headers_raw.split(",") if h.strip()]

    credentials = os.getenv("CORS_ALLOW_CREDENTIALS", "true").lower() == "true"

    return {
        "allow_origins": origins,
        "allow_methods": methods,
        "allow_headers": headers,
        "allow_credentials": credentials,
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, **_get_cors_settings())

# Include routers
app.include_router(UserRouter)
app.include_router(AdminRouter)


@app.get("/")
def read_root():
    """Root endpoint."""
    return "Hello world! I'm the authentication microservice."


@app.get("/jwt/public-key")
async def get_jwt_public_key():
    """Public endpoint to fetch JWT public key for token verification."""
    public_key = get_public_jwt_key()
    if not public_key:
        return {"status": "not_configured", "public_key": None}

    public_key = "".join(public_key.splitlines())

    return {"status": "ok", "algorithm": get_jwt_algorithm(), "public_key": public_key}


@app.get("/db_health")
async def check_database_health():
    """Check MongoDB health."""
    from database import _client, MONGODB_DB_NAME
    from models import User
    try:
        await _client.admin.command("ping")
        collections = await _client[MONGODB_DB_NAME].list_collection_names()
        user_count = await User.count()
        return {
            "status": "healthy",
            "database": "connected",
            "collections": collections,
            "user_count": user_count,
        }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e),
            "collections": [],
            "user_count": 0,
        }


@app.get("/create_tables")
async def create_tables_endpoint():
    """Re-initialize Beanie (recreates indexes)."""
    try:
        success = await init_db()
        if success:
            return {"status": "success", "message": "Beanie initialized and indexes created"}
        else:
            return {"status": "error", "message": "Failed to initialize Beanie"}
    except Exception as e:
        logger.error(f"Initialization failed: {e}")
        return {"status": "error", "message": str(e)}


@app.get("/drop_tables")
async def drop_tables_endpoint():
    """Drop all MongoDB collections (DANGEROUS - for development only!)."""
    from models import User, Device, RefreshToken
    try:
        dropped = []
        for model in [User, Device, RefreshToken]:
            collection_name = model.Settings.name
            await model.get_motor_collection().drop()
            dropped.append(collection_name)
        logger.warning(f"Dropped collections: {dropped}")
        return {
            "status": "success",
            "message": f"Dropped {len(dropped)} collections",
            "dropped_collections": dropped,
        }
    except Exception as e:
        logger.error(f"Failed to drop collections: {e}")
        return {"status": "error", "message": str(e)}


@app.get("/tables_info")
async def get_tables_info():
    """Get stats for all MongoDB collections."""
    from database import _client, MONGODB_DB_NAME
    from models import User, Device, RefreshToken
    try:
        db = _client[MONGODB_DB_NAME]
        collection_infos = []
        for model in [User, Device, RefreshToken]:
            collection_name = model.Settings.name
            count = await model.count()
            indexes = await model.get_motor_collection().index_information()
            collection_infos.append({
                "name": collection_name,
                "document_count": count,
                "indexes": list(indexes.keys()),
            })
        return {
            "status": "success",
            "collections": collection_infos,
            "total_collections": len(collection_infos),
        }
    except Exception as e:
        logger.error(f"Failed to get collection info: {e}")
        return {"status": "error", "message": str(e)}


@app.get("/simple_tables_html", response_class=HTMLResponse)
async def get_simple_tables_html():
    """Simple HTML view of all MongoDB collections."""
    from models import User, Device, RefreshToken
    try:
        html = "<html><body><h1>MongoDB Collections</h1>"

        for model in [User, Device, RefreshToken]:
            collection_name = model.Settings.name
            html += f"<h2>Collection: {collection_name}</h2>"
            docs = await model.find_all().to_list()

            if docs:
                html += "<table border='1'>"
                fields = list(docs[0].model_fields.keys())
                html += "<tr>" + "".join(f"<th>{f}</th>" for f in fields) + "</tr>"
                for doc in docs:
                    row_data = doc.model_dump()
                    html += "<tr>" + "".join(f"<td>{row_data.get(f)}</td>" for f in fields) + "</tr>"
                html += "</table>"
            else:
                html += "<p>Empty collection</p>"

            html += "<hr>"

        html += "</body></html>"
        return HTMLResponse(content=html)

    except Exception as e:
        return HTMLResponse(content=f"<h1>Error: {str(e)}</h1>", status_code=500)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
