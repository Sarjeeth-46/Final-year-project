import pandas as pd
import numpy as np
import glob
import os
import joblib
import zipfile
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from imblearn.over_sampling import SMOTE

# Configuration
DATA_DIR = "../Training data"
MODEL_PATH = "model_real.pkl"
# SAMPLE_SIZE_PER_FILE = 50000  # REMOVED: utilizing all data

def load_and_process_data():
    print("Searching for data...")
    zip_files = glob.glob(os.path.join(DATA_DIR, "*.zip"))
    
    if not zip_files:
        print("No zip files found!")
        return None

    dfs = []
    
    for zf in zip_files:
        print(f"Processing {os.path.basename(zf)}...")
        try:
            with zipfile.ZipFile(zf, 'r') as z:
                # Assume one CSV per zip
                csv_name = z.namelist()[0]
                with z.open(csv_name) as f:
                    # Read relevant columns
                    # We need: Destination Port, Flow Duration, Total Fwd Packets, Total Length of Fwd Packets, Label
                    # Note: Using 'usecols' to save memory during load if possible, but headers have spaces so it's tricky.
                    # Reading all for now, but in chunks if needed. For 2M rows, pandas usually handles it if you have 16GB RAM.
                    df = pd.read_csv(f)
                    
                    # Clean headers (strip spaces)
                    df.columns = df.columns.str.strip()
                    
                    # Feature Engineering
                    # Packet Size = Total Length / Total Packets
                    df['packet_size'] = df['Total Length of Fwd Packets'] / df['Total Fwd Packets'].replace(0, 1)
                    
                    # Select Features
                    # Selected: Destination Port, Flow Duration, Total Fwd Packets, Total Length of Fwd Packets, packet_size
                    required_cols = ['Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Length of Fwd Packets', 'packet_size', 'Label']
                    
                    # Check if all columns exist
                    if not all(col in df.columns for col in required_cols):
                         print(f"Skipping {zf} due to missing columns. Found: {df.columns.tolist()}")
                         continue

                    df_subset = df[required_cols].copy()
                    
                    # Rename for consistency
                    df_subset.columns = ['dest_port', 'flow_duration', 'total_fwd_packets', 'total_l_fwd_packets', 'packet_size', 'label']
                    
                    dfs.append(df_subset)
        except Exception as e:
            print(f"Error reading {zf}: {e}")

    if not dfs:
        return None
        
    print("Concatenating dataframes...")
    full_df = pd.concat(dfs, ignore_index=True)
    
    # Consolidate Labels
    def map_label(l):
        l = str(l).upper()
        if 'BENIGN' in l: return 'Normal'
        if 'DDOS' in l: return 'DDoS'
        if 'PORTSCAN' in l: return 'Port Scan'
        if 'BRUTE FORCE' in l or 'SSH-PATATOR' in l or 'FTP-PATATOR' in l: return 'Brute Force'
        if 'WEB ATTACK' in l: return 'Brute Force' 
        return 'Other'

    full_df['label_mapped'] = full_df['label'].apply(map_label)
    
    # Filter out 'Other'
    full_df = full_df[full_df['label_mapped'] != 'Other']
    
    print(f"Total processed samples: {len(full_df)}")
    print(full_df['label_mapped'].value_counts())
    
    return full_df

def train():
    df = load_and_process_data()
    if df is None:
        print("Training aborted.")
        return

    feature_cols = ['dest_port', 'flow_duration', 'total_fwd_packets', 'total_l_fwd_packets', 'packet_size']
    X = df[feature_cols]
    y = df['label_mapped']
    
    # Handle NaN/Inf
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    
    print("\n--- Feature Statistics ---")
    print(df.groupby('label_mapped')[feature_cols].mean())
    print("--------------------------\n")

    # Split
    print("Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Training
    print("Training Random Forest (n_estimators=100)... This may take a while.")
    # Increased estimators for better accuracy with large data
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced')
    rf.fit(X_train, y_train)
    
    print("Evaluating...")
    y_pred = rf.predict(X_test)
    print(classification_report(y_test, y_pred))
    
    # Save Metrics to JSON for Dashboard
    # Calculate metrics
    report = classification_report(y_test, y_pred, output_dict=True)
    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": report['weighted avg']['precision'],
        "recall": report['weighted avg']['recall'],
        "f1_score": report['weighted avg']['f1-score']
    }
    
    metrics_path = "model_metrics.json"
    import json
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f)
    print(f"Metrics saved to {metrics_path}")
    
    # Save
    joblib.dump(rf, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")
    
    # Save feature names for reference
    feature_names_path = "model_features.json"
    with open(feature_names_path, 'w') as f:
        json.dump(feature_cols, f)

if __name__ == "__main__":
    train()
