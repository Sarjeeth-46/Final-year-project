from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
import os
import json
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Network Threat Detection API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
JSON_DB_PATH = os.path.join(BASE_DIR, "threats.json")

# Database Connection Helper
# Database Connection Helper
def get_db_data():
    """Tries to fetch from MongoDB, falls back to JSON file."""
    try:
        # Try Mongo with a short timeout
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
        db = client["threat_detection"]
        # Check connection
        client.server_info()
        return list(db["threats"].find({}, {'_id': 0}).sort("timestamp", -1).limit(100))
    except ServerSelectionTimeoutError:
        # print("MongoDB not available. Serving from local JSON fallback.") # Reduce noise
        if os.path.exists(JSON_DB_PATH):
            with open(JSON_DB_PATH, 'r') as f:
                data = json.load(f)
                return sorted(data, key=lambda x: x['timestamp'], reverse=True)[:100]
        return []

def save_db_data(data):
    """Saves data back to JSON file (fallback mode only)."""
    if os.path.exists(JSON_DB_PATH):
        with open(JSON_DB_PATH, 'w') as f:
            json.dump(data, f, indent=2)

class ResolveRequest(BaseModel):
    status: str = "Resolved"
    note: Optional[str] = None

@app.post("/api/threats/{threat_id}/resolve")
def resolve_threat(threat_id: str):
    """Marks a threat as resolved."""
    # Logic for JSON fallback primarily
    if os.path.exists(JSON_DB_PATH):
        with open(JSON_DB_PATH, 'r') as f:
            data = json.load(f)
        
        updated = False
        target_threat = None
        
        for threat in data:
            if threat.get('id') == threat_id:
                threat['status'] = 'Resolved'
                target_threat = threat
                updated = True
                break
        
        if updated:
            with open(JSON_DB_PATH, 'w') as f:
                json.dump(data, f, indent=2)
            return target_threat
            
    raise HTTPException(status_code=404, detail="Threat not found")

@app.get("/api/threats")
def get_threats(status: Optional[str] = None):
    """Returns a list of detected threats sorted by timestamp."""
    data = get_db_data()
    if status and status.lower() != 'all':
        # Simple case-insensitive filter
        filter_status = 'Resolved' if status.lower() == 'resolved' else 'Active'
        # Handle default 'Active' if status is missing in JSON
        if filter_status == 'Active':
            data = [t for t in data if t.get('status', 'Active') != 'Resolved']
        else:
            data = [t for t in data if t.get('status') == filter_status]
    return data

@app.get("/api/stats/geo")
def get_geo_stats():
    """Returns aggregated threat counts by source country."""
    data = get_db_data()
    country_counts = {}
    for threat in data:
        country = threat.get("source_country", "USA") # Default to USA if missing
        country_counts[country] = country_counts.get(country, 0) + 1
    
    # Format for frontend: [{"id": "USA", "value": 10}, ...]
    return [{"id": k, "value": v} for k, v in country_counts.items()]

@app.get("/api/network/topology")
def get_topology():
    """Returns mock network topology status."""
    return {
        "nodes": [
            {"id": "firewall-1", "type": "Firewall", "status": "Healthy", "x": 100, "y": 50},
            {"id": "router-core", "type": "Router", "status": "Healthy", "x": 250, "y": 50},
            {"id": "switch-main", "type": "Switch", "status": "Warning", "x": 250, "y": 150},
            {"id": "server-db", "type": "Database", "status": "Healthy", "x": 150, "y": 250},
            {"id": "server-app", "type": "Server", "status": "Compromised", "x": 350, "y": 250},
            {"id": "workstation-1", "type": "Client", "status": "Healthy", "x": 100, "y": 350},
            {"id": "workstation-2", "type": "Client", "status": "Healthy", "x": 250, "y": 350},
            {"id": "workstation-3", "type": "Client", "status": "Healthy", "x": 400, "y": 350},
        ],
        "links": [
            {"source": "firewall-1", "target": "router-core"},
            {"source": "router-core", "target": "switch-main"},
            {"source": "switch-main", "target": "server-db"},
            {"source": "switch-main", "target": "server-app"},
            {"source": "switch-main", "target": "workstation-1"},
            {"source": "switch-main", "target": "workstation-2"},
            {"source": "switch-main", "target": "workstation-3"},
        ]
    }

@app.post("/api/threats/{threat_id}/block")
def block_threat(threat_id: str):
    """Mocks blocking a threat source."""
    return {"status": "blocked", "message": f"Source for threat {threat_id} has been blocked at the firewall."}

@app.get("/api/model/metrics")
def get_metrics():
    """Returns ML model performance metrics."""
    metrics_path = os.path.join(BASE_DIR, "model_metrics.json")
    if os.path.exists(metrics_path):
        with open(metrics_path, 'r') as f:
            return json.load(f)
    return {"error": "Metrics not found"}

@app.get("/api/model/features")
def get_features():
    """Returns ML feature importance rankings."""
    path = os.path.join(BASE_DIR, "feature_importance.json")
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return []

@app.get("/api/threats/risk-summary")
def get_risk_summary():
    """Returns aggregated count of threats by risk level."""
    threats = get_db_data()
    # Risk Levels: Critical (0.8-1.0), High (0.6-0.8), Medium (0.3-0.6), Low (0-0.3)
    # Note: Risk Score in DB is 0-100. So: 80-100, 60-80, 30-60, 0-30
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    
    for t in threats:
        s = t.get('risk_score', 0)
        if s >= 80: summary["Critical"] += 1
        elif s >= 60: summary["High"] += 1
        elif s >= 30: summary["Medium"] += 1
        else: summary["Low"] += 1
        
    # Return in list format for Recharts
    return [{"name": k, "value": v} for k, v in summary.items()]

@app.get("/api/stats/attack-types")
def get_attack_types():
    """Returns count of threats by attack type for Pie Chart."""
    data = get_db_data()
    counts = {}
    for t in data:
        label = t.get('predicted_label', 'Unknown')
        counts[label] = counts.get(label, 0) + 1
    
    return [{"name": k, "value": v} for k, v in counts.items()]

@app.get("/api/alerts/critical")
def get_critical_alerts():
    """Returns top 3 most recent critical threats."""
    data = get_db_data()
    # Filter for Critical (>= 80) and active
    critical = [t for t in data if t.get('risk_score', 0) >= 80 and t.get('status') != 'Resolved']
    # Return top 3
    return critical[:3]

@app.get("/api/threats/high-risk")
def get_high_risk_threats():
    """Returns only High and Critical threats."""
    threats = get_db_data()
    # Filter > 60
    high_risk = [t for t in threats if t.get('risk_score', 0) >= 60]
    return high_risk

@app.get("/api/stats/history")
def get_history():
    """Returns threat history over time (Mocked for Phase 3)."""
    # In real app: Aggregate timestamps from DB by minute
    # Here: Returning mock trend data
    return [
        {"time": "10:00", "count": 12},
        {"time": "10:05", "count": 19},
        {"time": "10:10", "count": 8},
        {"time": "10:15", "count": 25}, # Spike
        {"time": "10:20", "count": 14},
    ]

@app.get("/api/health")
def health_check():
    """System Health Monitoring."""
    status = {
        "status": "healthy",
        "components": {
            "api": "online",
            "model_loaded": os.path.exists("backend/model.pkl"),
            "database": "connected" if "threat_detection" in str(MONGO_URI) or os.path.exists(JSON_DB_PATH) else "offline"
        }
    }
    return status

@app.get("/api/threats/aggregated")
def get_aggregated_threats():
    """
    Groups alerts by Source IP and Attack Type to reduce alert fatigue.
    Returns: source_ip, attack_type, count, avg_confidence, max_risk, last_seen
    """
    threats = get_db_data()
    aggregation = {}
    
    for t in threats:
        key = (t['source_ip'], t['predicted_label'])
        if key not in aggregation:
            aggregation[key] = {
                "source_ip": t['source_ip'],
                "attack_type": t['predicted_label'],
                "count": 0,
                "total_confidence": 0,
                "max_risk": 0,
                "last_seen": t['timestamp']
            }
        
        agg = aggregation[key]
        agg["count"] += 1
        agg["total_confidence"] += t.get('attack_probability', 0)
        agg["max_risk"] = max(agg["max_risk"], t.get('risk_score', 0))
        if t['timestamp'] > agg["last_seen"]:
            agg["last_seen"] = t['timestamp']
            
    # Format output
    result = []
    for agg in aggregation.values():
        agg["avg_confidence"] = round(agg["total_confidence"] / agg["count"], 2)
        del agg["total_confidence"]
        result.append(agg)
        
    return sorted(result, key=lambda x: x['max_risk'], reverse=True)

@app.get("/api/stats")
def get_stats():
    """Returns statistics for the dashboard charts."""
    # Reuse risk logic or keep simple
    return get_risk_summary()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
