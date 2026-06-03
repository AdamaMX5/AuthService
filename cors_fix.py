# cors_fix.py - Korrekte CORS Header für alle Responses
from fastapi.middleware.cors import CORSMiddleware
import os

def fix_cors_middleware():
    Erstellt CORSMiddleware mit korrekter Header-Setzung für alle Responses
    
    # Get CORS configuration from environment
    cors_origins = os.getenv(CORS_ORIGINS, *)
    
    if cors_origins == *:
        allow_origins = [*]
    else:
        allow_origins = [origin.strip() for origin in cors_origins.split(,) if origin.strip()]
    
    methods_raw = os.getenv(CORS_METHODS, *)
    methods = [m.strip() for m in methods_raw.split(,) if m.strip()]
    
    headers_raw = os.getenv(CORS_HEADERS, *)
    headers = [h.strip() for h in headers_raw.split(,) if h.strip()]
    
    credentials = os.getenv(CORS_ALLOW_CREDENTIALS, true).lower() == true
    
    return CORSMiddleware(
        allow_origins=allow_origins,
        allow_methods=methods,
        allow_headers=headers,
        allow_credentials=credentials,
        expose_headers=[*],  # Wichtig: Alle Header exposieren
        max_age=600,
    )
