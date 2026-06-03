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
