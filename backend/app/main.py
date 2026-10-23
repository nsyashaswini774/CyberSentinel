from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.database import Base, engine
from app.models import scan  # Register models with metadata
from app.api.v1.router import api_router

# Initialize database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
)

# Enable CORS for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Root status route
@app.get("/")
def read_root():
    return {
        "project": settings.PROJECT_NAME,
        "status": "operational",
        "docs": f"{settings.API_V1_STR}/docs",
    }

# Include API v1 routes
app.include_router(api_router, prefix=settings.API_V1_STR)
