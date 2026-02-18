from fastapi import FastAPI

from app.routers.health_router import router as HealthRouter

app = FastAPI(title="MicroService Template")
app.include_router(HealthRouter)


@app.get("/")
async def root() -> dict[str, str]:
    return {"service": "microservice-template", "status": "running"}
