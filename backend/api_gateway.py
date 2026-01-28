"""
Project: AegisCore
Module: Application Controller (API Gateway)
Description:
    The centralized REST interface for the security platform.
    Routes incoming HTTP requests to the appropriate Business Logic component
    (IncidentManager, MetricPipeline, AuthProvider).
    
    Adheres to the OpenAPI v3 specification.
"""
import uvicorn
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List
from pydantic import BaseModel

# Configuration & Infrastructure
from backend.core.config import config
from backend.services.auth_service import auth_service
from backend.core.database import db

# Business Logic Services
from backend.services.threat_service import threat_service as incident_manager
from backend.services.analytics_service import analytics_service as metric_pipeline
from backend.services.topology_service import topology_service

# --- Data Transfer Objects (DTOs) ---
class CredentialsDTO(BaseModel):
    """Schema for authentication payload."""
    username: str
    password: str

class PasswordChangeDTO(BaseModel):
    """Schema for password rotation."""
    username: str
    old_password: str
    new_password: str

# --- Application Initialization ---
app = FastAPI(
    title=config.API_TITLE,
    version=config.API_VERSION,
    description="Enterprise Security Operations Center (SOC) API"
)

# Security Middleware (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Lifecycle Hooks ---
@app.on_event("startup")
def bootstrap_system():
    """Initializes critical system components on startup."""
    # Ensure default administrator exists for first-run
    auth_service.ensure_admin_user()


# --- Authentication Endpoints ---
@app.post("/api/auth/login")
def authenticate_operator(creds: CredentialsDTO):
    """Validates operator credentials and issues a session token."""
    token = auth_service.authenticate_user(creds.username, creds.password)
    if not token:
        raise HTTPException(status_code=401, detail="Authentication Failed: Invalid credentials")
    return {"access_token": token, "token_type": "bearer"}

@app.post("/api/auth/change-password")
def rotate_operator_credentials(req: PasswordChangeDTO):
    """Updates the credentials for the specified operator."""
    success = auth_service.change_password(req.username, req.old_password, req.new_password)
    if not success:
        raise HTTPException(status_code=400, detail="Rotation Failed: Verification error.")
    return {"message": "Credentials updated successfully"}


# --- Incident Management Endpoints ---
@app.get("/api/threats")
def retrieve_incident_feed(status: Optional[str] = None):
    """
    Returns a stream of security incidents.
    Optional: Filter by lifecycle state (e.g., 'Active', 'Resolved').
    """
    return incident_manager.get_recent_threats(status_filter=status)

@app.post("/api/threats/{threat_id}/resolve")
def triage_incident(threat_id: str):
    """Transitions an incident to the 'Resolved' state."""
    result = incident_manager.resolve_threat(threat_id)
    if not result:
        raise HTTPException(status_code=404, detail="Incident ID not found.")
    return result

@app.post("/api/threats/{threat_id}/block")
def execute_mitigation(threat_id: str):
    """Triggers an automated block response against the source."""
    success = incident_manager.block_threat_source(threat_id)
    if success:
        return {"status": "blocked", "message": f"Mitigation applied for Incident {threat_id}."}
    raise HTTPException(status_code=500, detail="Mitigation execution failed.")


# --- Analytics & Reporting Endpoints ---
@app.get("/api/dashboard/summary")
def get_executive_summary():
    """Returns the aggregated intelligence definition for the main dashboard."""
    return metric_pipeline.get_dashboard_summary()

# Specialized Micro-endpoints for granular UI components
@app.get("/api/stats/attack-types")
def get_vector_distribution():
    return metric_pipeline.get_dashboard_summary()["attack_types"]

@app.get("/api/stats/geo")
def get_geographic_distribution():
    return metric_pipeline.get_dashboard_summary()["geo_stats"]

@app.get("/api/stats/risk-summary")
def get_severity_distribution():
    return metric_pipeline.get_dashboard_summary()["risk_summary"]

@app.get("/api/network/topology")
def get_network_graph():
    """Provides node-link data for network visualization."""
    return topology_service.get_topology_status()


# --- System & Health Endpoints ---
@app.get("/api/health")
def system_health_check():
    """Diagnostic heartbeat."""
    return {
        "status": "online",
        "api_version": config.API_VERSION,
        "mode": "production" if db.get_db() else "resiliency_fallback"
    }


# --- Artifact Retrieval Endpoints ---
@app.get("/api/model/metrics")
def retrieve_model_performance():
    """Exposes ML performance metrics (Accuracy, F1, etc.)."""
    import json, os
    if os.path.exists(config.METRICS_PATH):
        try:
            with open(config.METRICS_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {}

@app.get("/api/model/features")
def retrieve_model_explainability():
    """Exposes feature importance for XAI visualization."""
    import json, os
    if os.path.exists(config.FEATURES_PATH):
        try:
            with open(config.FEATURES_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return []

# --- Legacy Hooks (Backward Compatibility) ---
@app.get("/api/threats/risk-summary")
def _legacy_risk_hook(): 
    return get_severity_distribution()

@app.get("/api/alerts/critical")
def _legacy_critical_hook():
    return metric_pipeline.get_dashboard_summary()["critical_alerts"]

@app.get("/api/stats/history")
def _legacy_history_hook():
    # Mock data for deprecated history widget
    return [
        {"time": "10:00", "count": 12}, {"time": "10:05", "count": 19},
        {"time": "10:10", "count": 8},  {"time": "10:15", "count": 25}, 
        {"time": "10:20", "count": 14}
    ]

if __name__ == "__main__":
    uvicorn.run("backend.api_gateway:app", host="0.0.0.0", port=8000, reload=True)
