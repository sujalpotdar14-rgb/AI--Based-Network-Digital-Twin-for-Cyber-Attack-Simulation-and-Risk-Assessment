import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, accuracy_score, f1_score, confusion_matrix

try:
    from dataset_generator import generate_network_telemetry_dataset
except ImportError:
    from ml.dataset_generator import generate_network_telemetry_dataset

FEATURE_COLUMNS = [
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "packet_length_mean",
    "syn_flag_ratio",
    "error_rate",
    "failed_logins",
    "cvss_score",
    "asset_criticality",
    "node_centrality",
    "port_entropy"
]

def train_and_save_models():
    print("[*] Starting AI Model Training Pipeline for Network Digital Twin...")
    
    # 1. Dataset Loading / Generation
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    csv_path = os.path.join(data_dir, "network_telemetry.csv")
    
    if not os.path.exists(csv_path):
        df = generate_network_telemetry_dataset()
    else:
        df = pd.read_csv(csv_path)
        
    X = df[FEATURE_COLUMNS]
    y = df["label"]
    
    # 2. Train / Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    
    # 3. Standard Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # 4. Threat Classifier (Random Forest)
    print("[*] Training Random Forest Threat Classifier...")
    clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=12,
        random_state=42,
        class_weight="balanced"
    )
    clf.fit(X_train_scaled, y_train)
    
    y_pred = clf.predict(X_test_scaled)
    acc = float(accuracy_score(y_test, y_pred))
    macro_f1 = float(f1_score(y_test, y_pred, average="macro"))
    print(f"[+] Classifier Training Complete! Accuracy: {acc*100:.2f}%, Macro F1: {macro_f1*100:.2f}%")
    
    report = classification_report(y_test, y_pred, output_dict=True)
    labels_list = sorted(list(set(y)))
    cm = confusion_matrix(y_test, y_pred, labels=labels_list).tolist()
    
    feature_importances = {
        feat: float(imp)
        for feat, imp in zip(FEATURE_COLUMNS, clf.feature_importances_)
    }
    
    # 5. Anomaly Detector (Isolation Forest)
    print("[*] Training Isolation Forest Anomaly Detector...")
    # Train anomaly detector on Normal samples
    normal_mask = (y_train == "Normal")
    iso = IsolationForest(
        n_estimators=100,
        contamination=0.08,
        random_state=42
    )
    iso.fit(X_train_scaled[normal_mask])
    
    # 6. Save Artifacts
    models_dir = os.path.join(os.path.dirname(__file__), "..", "models")
    os.makedirs(models_dir, exist_ok=True)
    
    clf_path = os.path.join(models_dir, "threat_classifier.pkl")
    iso_path = os.path.join(models_dir, "anomaly_detector.pkl")
    scaler_path = os.path.join(models_dir, "scaler.pkl")
    metadata_path = os.path.join(models_dir, "model_metadata.json")
    
    joblib.dump(clf, clf_path)
    joblib.dump(iso, iso_path)
    joblib.dump(scaler, scaler_path)
    
    metadata = {
        "accuracy": round(acc, 4),
        "macro_f1": round(macro_f1, 4),
        "feature_names": FEATURE_COLUMNS,
        "classes": labels_list,
        "confusion_matrix": cm,
        "feature_importances": feature_importances,
        "classification_report": report
    }
    
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
        
    print(f"[+] All models and metadata successfully saved to: {models_dir}")
    return metadata

if __name__ == "__main__":
    train_and_save_models()
