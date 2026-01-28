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
SAMPLE_SIZE_PER_FILE = 50000  # Cap rows per file for speed

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
                    # Read only necessary columns to save memory
                    # Destination Port, Total Fwd Packets, Total Length of Fwd Packets, Label
                    # Note: Headers might have spaces, so we might need to be careful
                    # Based on previous view: " Destination Port", " Total Fwd Packets", "Total Length of Fwd Packets", " Label"
                    # We'll read all and strip
                    df = pd.read_csv(f, nrows=SAMPLE_SIZE_PER_FILE)
                    
                    # Clean headers (strip spaces)
                    df.columns = df.columns.str.strip()
                    
                    # Feature Engineering
                    # Packet Size = Total Length / Total Packets
                    # Avoid division by zero
                    df['packet_size'] = df['Total Length of Fwd Packets'] / df['Total Fwd Packets'].replace(0, 1)
                    
                    # Select Features
                    df_subset = df[['Destination Port', 'packet_size', 'Label']].copy()
                    df_subset.columns = ['dest_port', 'packet_size', 'label']
                    
                    dfs.append(df_subset)
        except Exception as e:
            print(f"Error reading {zf}: {e}")

    if not dfs:
        return None
        
    full_df = pd.concat(dfs, ignore_index=True)
    
    # Consolidate Labels
    # CIC-IDS2017 has many labels like "DDoS", "PortScan", "BENIGN", "Web Attack - Brute Force"
    # Map to: Normal, DDoS, Port Scan, Brute Force
    
    def map_label(l):
        l = str(l).upper()
        if 'BENIGN' in l: return 'Normal'
        if 'DDOS' in l: return 'DDoS'
        if 'PORTSCAN' in l: return 'Port Scan'
        if 'BRUTE FORCE' in l or 'SSH-PATATOR' in l or 'FTP-PATATOR' in l: return 'Brute Force'
        if 'WEB ATTACK' in l: return 'Brute Force' 
        return 'Other' # Infiltration, Bot, etc.

    full_df['label_mapped'] = full_df['label'].apply(map_label)
    
    # Filter out 'Other' to keep model focused, or map to closest
    full_df = full_df[full_df['label_mapped'] != 'Other']
    
    print(f"Total processed samples: {len(full_df)}")
    print(full_df['label_mapped'].value_counts())
    
    return full_df

def train():
    df = load_and_process_data()
    if df is None:
        print("Training aborted.")
        return

    X = df[['dest_port', 'packet_size']]
    y = df['label_mapped']
    
    # Handle NaN/Inf
    X = X.replace([np.inf, -np.inf], np.nan).dropna()
    y = y[X.index] # Align y with dropped X rows

    # Statistics for Generator Tuning
    print("\n--- Feature Statistics for Simulator Tuning ---")
    stats = df.groupby('label_mapped').agg({
        'packet_size': ['mean', 'min', 'max', 'std'],
        'dest_port': lambda x: x.mode()[0] # Most common port
    })
    print(stats)
    print("-----------------------------------------------\n")

    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Balance (smote is expensive on large data, maybe simple undersampling or class_weight is better? Stick to SMOTE for now but careful)
    # Actually, let's limit training size for quick turnaround if massive
    if len(X_train) > 100000:
        print("Downsampling for training speed...")
        # Simple random sample
        idx = np.random.choice(X_train.index, 100000, replace=False)
        X_train = X_train.loc[idx]
        y_train = y_train.loc[idx]

    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1, class_weight='balanced')
    rf.fit(X_train, y_train)
    
    print("Evaluating...")
    y_pred = rf.predict(X_test)
    print(classification_report(y_test, y_pred))
    
    # Save
    joblib.dump(rf, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    train()
