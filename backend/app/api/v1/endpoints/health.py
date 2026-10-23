from fastapi import APIRouter
from app.schemas.email import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["System"])
def get_system_health():
    """Health check endpoint to verify backend operational status."""
    return HealthResponse()
