
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.limiter import limiter
from app.routers.domain import router as domain_router

app = FastAPI(
    title="Email & Domain Health Checker",
    version="1.0.0",
)

app.state.limiter = limiter

app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,
)

app.include_router(domain_router)

STATIC_DIR = Path(__file__).resolve().parent / "static"


@app.get("/", include_in_schema=False)
def homepage():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health_check():
    return {"status": "healthy"}
