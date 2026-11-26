"""
AI-Based Intrusion Detection System (AI-IDS)
Traffic Monitoring & Flow Ingestion Router
"""

import os
import io
import pandas as pd
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, status
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.models.traffic import TrafficRecord
from app.schemas.traffic_schemas import TrafficRecordResponse, BatchAnalysisSummary
from app.services.traffic_service import TrafficService
from app.services.live_simulation_service import LiveMonitorService
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/traffic", tags=["Traffic Monitoring"])

@router.get("/records", response_model=List[TrafficRecordResponse])
def get_records(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    threat_only: Optional[bool] = None,
    attack_type: Optional[str] = None,
    search_ip: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve network traffic flow records with multi-criteria filtering."""
    return TrafficService.get_traffic_records(
        db=db,
        skip=skip,
        limit=limit,
        threat_only=threat_only,
        attack_type=attack_type,
        search_ip=search_ip
    )

@router.post("/upload-csv", response_model=BatchAnalysisSummary)
async def upload_csv_dataset(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Upload a CSV network traffic flow dataset (e.g. CICIDS2017 format).
    Runs real Random Forest classification pipeline on all records, saves results, and generates security alerts.
    """
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Only CSV files are supported."
        )

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded file is empty."
        )

    try:
        df = pd.read_csv(io.BytesIO(content))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to parse CSV file: {str(e)}"
        )

    if len(df) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CSV file contains zero records."
        )

    # Process batch with ML pipeline
    summary = TrafficService.process_csv_dataframe(
        df=df,
        filename=file.filename,
        db=db,
        source_type="CSV_UPLOAD"
    )

    return summary

@router.get("/sample-files")
def list_sample_datasets(current_user: User = Depends(get_current_user)):
    """List available benchmark sample CSV datasets that users can directly test."""
    files = []
    if os.path.exists(settings.SAMPLE_DATA_DIR):
        for fname in os.listdir(settings.SAMPLE_DATA_DIR):
            if fname.endswith(".csv"):
                fpath = os.path.join(settings.SAMPLE_DATA_DIR, fname)
                size_kb = round(os.path.getsize(fpath) / 1024, 1)
                files.append({
                    "filename": fname,
                    "size_kb": size_kb,
                    "description": "CICIDS2017 Benchmark Flow Traffic Sample"
                })
    return files

@router.post("/load-sample/{filename}", response_model=BatchAnalysisSummary)
def load_sample_dataset(
    filename: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Directly ingest and classify one of the bundled benchmark sample CSV files."""
    filepath = os.path.join(settings.SAMPLE_DATA_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample file {filename} not found."
        )

    try:
        df = pd.read_csv(filepath)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed reading sample dataset: {str(e)}"
        )

    summary = TrafficService.process_csv_dataframe(
        df=df,
        filename=filename,
        db=db,
        source_type="SAMPLE_BENCHMARK"
    )
    return summary

@router.get("/live-status")
def get_live_status(current_user: User = Depends(get_current_user)):
    """Get status of optional live traffic monitoring mode."""
    return {"is_active": LiveMonitorService.is_active()}

@router.post("/toggle-live")
def toggle_live_monitor(
    enable: bool = Query(...),
    current_user: User = Depends(get_current_user)
):
    """Enable or disable optional live traffic monitoring mode."""
    LiveMonitorService.set_active(enable)
    return {
        "is_active": LiveMonitorService.is_active(),
        "message": f"Live monitoring mode {'activated' if enable else 'paused'}."
    }

@router.post("/generate-live-flow")
def generate_live_flow(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generate and classify a single live network flow event with real ML."""
    return LiveMonitorService.generate_single_live_flow(db)
