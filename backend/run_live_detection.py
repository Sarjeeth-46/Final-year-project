from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
import pandas as pd
import joblib
import time
import uuid
from log_generator import generate_log_entry
from detector import calculate_risk_score
import os
import json
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = "threat_detection"
COLLECTION_NAME = "threats"
JSON_DB_PATH = "threats.json"
MODEL_PATH = "model_real.pkl"

def run_detection(num_records=50):
    print("Initializing Live Detection Simulation...")
    
    # Load Real Model
    try:
        model = joblib.load(MODEL_PATH)
        print(f"Loaded {MODEL_PATH}")
    except Exception as e:
        print(f"Error loading model: {e}")
        return

    # Database Setup
    mongo_available = False
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
        client.server_info()
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]
        mongo_available = True
    except:
        print("MongoDB unavailable. Using local JSON.")

    print(f"Processing {num_records} live traffic events...")
    
    threats_to_insert = []
    ip_alert_counts = {} # Trace repeat offenders in this batch/session
    
    for _ in range(num_records):
        log = generate_log_entry()
        
        # Prepare Input for Model: ['dest_port', 'packet_size']
        input_data = pd.DataFrame([{
            'dest_port': log['dest_port'],
            'packet_size': log['packet_size']
        }])
        
        # Predict
        try:
            probs = model.predict_proba(input_data)[0]
            classes = model.classes_
            prediction = model.predict(input_data)[0]
            class_idx = list(classes).index(prediction)
            confidence = probs[class_idx]
            
            # Risk Calc
            risk = calculate_risk_score(confidence, prediction)
            
            if prediction != 'Normal':
                # Temporal Analysis: Check for Repeat Offender
                src = log['source_ip']
                ip_alert_counts[src] = ip_alert_counts.get(src, 0) + 1
                
                escalation_flag = False
                if ip_alert_counts[src] > 1: # Low threshold for demo (usually > 5)
                    risk = min(risk * 1.2, 100.0) # Escalate Risk
                    escalation_flag = True
                    print(f"ESCALATION: Repeat offender {src} detected! Risk bumped to {risk}")

                print(f"DETECTED: {prediction} from {src} (Risk: {risk})")
                
                threat = {
                    "id": str(uuid.uuid4()),
                    "timestamp": log['timestamp'],
                    "source_ip": log['source_ip'],
                    "destination_ip": log['dest_ip'],
                    "destination_port": log['dest_port'],
                    "protocol": log['protocol'],
                    "packet_size": log['packet_size'],
                    "predicted_label": prediction,
                    "confidence": float(confidence),
                    "risk_score": risk,
                    "status": "Active",
                    "escalation_flag": escalation_flag
                }
                threats_to_insert.append(threat)
                
        except Exception as e:
            print(f"Prediction error: {e}")

    # Save to Storage
    if threats_to_insert:
        if mongo_available:
            collection.insert_many(threats_to_insert)
            
        # Update JSON for Frontend Fallback
        current_data = []
        if os.path.exists(JSON_DB_PATH):
            try:
                with open(JSON_DB_PATH, 'r') as f:
                    current_data = json.load(f)
            except:
                pass
        
        # Prepend new threats (latest first)
        current_data = threats_to_insert + current_data
        # Keep manageable size
        current_data = current_data[:200]
        
        with open(JSON_DB_PATH, 'w') as f:
            json.dump(current_data, f, indent=2)
            
        print(f"Successfully registered {len(threats_to_insert)} new threats.")
    else:
        print("No threats detected in this batch.")

if __name__ == "__main__":
    run_detection()
