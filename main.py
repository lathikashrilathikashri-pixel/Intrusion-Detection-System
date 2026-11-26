"""
AI-Based Intrusion Detection System (AI-IDS)
Project Code: RW-CS-001 | Organization: RW Software Solutions
FastAPI Application Entrypoint
"""

import sys
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.config import settings
from app.database import engine, Base, SessionLocal
from app.models import user, traffic
from app.services.auth_service import init_admin_user
from app.services.traffic_service import TrafficService

if settings.BASE_DIR not in sys.path:
    sys.path.append(settings.BASE_DIR)

from ml.predictor import IDSInferenceEngine

# Import Routers
from app.routers.auth import router as auth_router
from app.routers.dashboard import router as dashboard_router
from app.routers.traffic import router as traffic_router
from app.routers.detection import router as detection_router
from app.routers.alerts import router as alerts_router
from app.routers.model import router as model_router
from app.routers.reports import router as reports_router
from app.routers.settings import router as settings_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup & shutdown events."""
    print("[AI-IDS] Initializing database tables...")
    Base.metadata.create_all(bind=engine)

    # Initialize default admin user and sample data
    db = SessionLocal()
    try:
        init_admin_user(db)
        
        # Load ML model
        print("[AI-IDS] Loading Machine Learning Random Forest Model...")
        engine_ml = IDSInferenceEngine.get_instance()
        if not engine_ml.is_loaded:
            engine_ml.load_artifacts()
            
        # Seed sample benchmark traffic if DB is empty
        TrafficService.seed_initial_sample_data(db)
    finally:
        db.close()

    print("[AI-IDS] Backend service is fully online and ready for SOC operations.")
    yield
    print("[AI-IDS] Shutting down backend service.")

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Enterprise AI-Powered Security Operations Center & Intrusion Detection System",
    version=settings.VERSION,
    lifespan=lifespan
)

# CORS Middleware (allows React frontend to communicate seamlessly)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Routers under /api
app.include_router(auth_router, prefix=settings.API_PREFIX)
app.include_router(dashboard_router, prefix=settings.API_PREFIX)
app.include_router(traffic_router, prefix=settings.API_PREFIX)
app.include_router(detection_router, prefix=settings.API_PREFIX)
app.include_router(alerts_router, prefix=settings.API_PREFIX)
app.include_router(model_router, prefix=settings.API_PREFIX)
app.include_router(reports_router, prefix=settings.API_PREFIX)
app.include_router(settings_router, prefix=settings.API_PREFIX)

@app.get("/api/health")
def health_check():
    return {
        "system": settings.PROJECT_NAME,
        "code": settings.PROJECT_CODE,
        "organization": settings.ORGANIZATION,
        "status": "OPERATIONAL",
        "docs_url": "/docs",
        "version": settings.VERSION
    }

# Mount Production React Frontend if built
frontend_dist = os.path.join(settings.BASE_DIR, "frontend", "dist")
if os.path.exists(frontend_dist):
    assets_dir = os.path.join(frontend_dist, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        if full_path.startswith("api/") or full_path == "api":
            raise HTTPException(status_code=404, detail="API route not found")
        target_file = os.path.join(frontend_dist, full_path)
        if full_path and os.path.exists(target_file) and os.path.isfile(target_file):
            return FileResponse(target_file)
        return FileResponse(os.path.join(frontend_dist, "index.html"))
else:
    @app.get("/")
    def root():
        return {
            "system": settings.PROJECT_NAME,
            "code": settings.PROJECT_CODE,
            "organization": settings.ORGANIZATION,
            "status": "OPERATIONAL",
            "docs_url": "/docs",
            "frontend_status": "Run `cd frontend; npm run dev` for Vite frontend."
        }
