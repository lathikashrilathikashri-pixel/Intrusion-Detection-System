"""
AI-Based Intrusion Detection System (AI-IDS)
Project Code: RW-CS-001 | Organization: RW Software Solutions
Main Application Runner
"""

import os
import sys
import uvicorn

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(BASE_DIR, 'backend'))
sys.path.append(BASE_DIR)

def verify_system():
    print("=" * 70)
    print(" AI-BASED INTRUSION DETECTION SYSTEM (AI-IDS) - SOC PLATFORM")
    print(" Project Code: RW-CS-001 | Organization: RW Software Solutions")
    print("=" * 70)

    # 1. Verify ML Model Artifacts
    models_dir = os.path.join(BASE_DIR, 'ml', 'models')
    model_path = os.path.join(models_dir, 'rf_ids_model.joblib')
    
    if not os.path.exists(model_path):
        print("\n[AI-IDS] ML model artifacts not found. Initiating model training pipeline...")
        from ml.train import train_ids_model
        train_ids_model(n_samples=25000)
    else:
        print("[AI-IDS] Found trained Random Forest model and preprocessors.")

    # 2. Database verification
    db_path = os.path.join(BASE_DIR, 'database', 'ids_database.db')
    if os.path.exists(db_path):
        print(f"[AI-IDS] SQLite database verified at {db_path}")
    else:
        print("[AI-IDS] Database will be initialized on server start.")

    print("\n" + "=" * 70)
    print(" STARTING ENTERPRISE SOC APPLICATION SERVER")
    print(" Dashboard URL:  http://127.0.0.1:8000")
    print(" API Docs (SW):  http://127.0.0.1:8000/docs")
    print(" Default Login:  admin / Admin@123")
    print("=" * 70 + "\n")

if __name__ == '__main__':
    verify_system()
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        app_dir=os.path.join(BASE_DIR, 'backend'),
        reload=False
    )
