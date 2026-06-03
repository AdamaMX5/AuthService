import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI()

# Simulate the _get_cors_settings function
def _get_cors_settings():
    origins = [o.strip() for o in os.getenv(CORS_ORIGINS, ).split(,) if o.strip()]
    if not origins:
        origins = [*]
    
    methods_raw = os.getenv(CORS_METHODS, *)
    methods = [m.strip() for m in methods_raw.split(,) if m.strip()]
    
    headers_raw = os.getenv(CORS_HEADERS, *)
    headers = [h.strip() for h in headers_raw.split(,) if h.strip()]
    
    credentials = os.getenv(CORS_ALLOW_CREDENTIALS, true).lower() == true
    
    return {
        allow_origins: origins,
        allow_methods: methods,
        allow_headers: headers,
        allow_credentials: credentials,
    }

# Add CORS middleware
settings = _get_cors_settings()
app.add_middleware(CORSMiddleware, **settings)

# Add manual OPTIONS handler for all routes
@app.options(/{path:path})
async def options_handler(request: Request, path: str):
    Handle OPTIONS requests manually to ensure CORS headers are set.
    origin = request.headers.get(origin)
    
    # Check if origin is allowed
    allowed_origins = settings[allow_origins]
    if allowed_origins == [*]:
        response_origin = *
    elif origin in allowed_origins:
        response_origin = origin
    else:
        response_origin = None
    
    headers = {}
    if response_origin:
        headers[Access-Control-Allow-Origin] = response_origin
        if settings[allow_credentials]:
            headers[Access-Control-Allow-Credentials] = true
    
    if settings[allow_methods]:
        headers[Access-Control-Allow-Methods] = , .join(settings[allow_methods])
    
    if settings[allow_headers]:
        headers[Access-Control-Allow-Headers] = , .join(settings[allow_headers])
    
    return JSONResponse(content={}, headers=headers)

# Test endpoint
@app.get(/test)
async def test():
    return {message: Test endpoint}

if __name__ == __main__:
    import uvicorn
    uvicorn.run(app, host=0.0.0.0, port=8000)
