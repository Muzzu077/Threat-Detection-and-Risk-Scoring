"""
ML Detection Engine — LightGBM Classifier Pipeline
Trained on labeled log data (normal, brute_force, sql_injection, data_exfiltration, port_scan)
Provides: train, predict, and metrics functions.
"""
import os
import json
import numpy as np
import pandas as pd
import joblib
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, classification_report, confusion_matrix
)

# Optional LightGBM — gracefully fall back to RandomForest
try:
    from lightgbm import LGBMClassifier
    LGBM_AVAILABLE = True
except ImportError:
    LGBM_AVAILABLE = False

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ML_MODEL_PATH = os.path.join(_PROJECT_ROOT, "data", "ml_model.pkl")
ML_ENCODERS_PATH = os.path.join(_PROJECT_ROOT, "data", "ml_encoders.pkl")
ML_METRICS_PATH = os.path.join(_PROJECT_ROOT, "data", "ml_metrics.json")

ATTACK_CLASSES = ["normal", "brute_force", "sql_injection", "data_exfiltration", "port_scan"]
CATEGORICAL_COLS = ["user", "role", "action", "status", "resource"]
NETWORK_FEATURES = [
    'flow_duration', 'total_fwd_packets', 'total_bwd_packets',
    'flow_bytes_per_s', 'flow_packets_per_s',
    'fwd_packet_length_mean', 'bwd_packet_length_mean',
    'flow_iat_mean', 'fwd_psh_flags', 'syn_flag_count',
    'rst_flag_count', 'ack_flag_count', 'down_up_ratio',
    'active_mean', 'idle_mean'
]


def _build_features(df: pd.DataFrame, encoders: dict) -> np.ndarray:
    """Encode + scale features from a raw log DataFrame."""
    X = pd.DataFrame()
    for col in CATEGORICAL_COLS:
        le = encoders.get(col)
        if le is None:
            X[col] = 0
            continue
        df[col] = df[col].astype(str)
        le_map = dict(zip(le.classes_, le.transform(le.classes_)))
        X[col] = df[col].map(le_map).fillna(0)

    # Numeric features
    if "hour" in df.columns:
        X["hour"] = df["hour"].fillna(0)
    else:
        X["hour"] = 0

    # Network features (optional — skip if not present in data)
    for feat in NETWORK_FEATURES:
        if feat in df.columns:
            X[feat] = df[feat].fillna(0)

    scaler: StandardScaler = encoders.get("scaler")
    if scaler:
        return scaler.transform(X)
    return X.values


def train_ml_engine(data_path: str = os.path.join(_PROJECT_ROOT, "data", "labeled_logs.csv")) -> dict:
    """
    Train a LightGBM (or RandomForest) classifier on labeled log data.
    Returns a metrics dict with Accuracy, Precision, Recall, F1.
    """
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Labeled dataset not found at {data_path}. Run utils/train_ml_engine.py first.")

    df = pd.read_csv(data_path)
    print(f"📊 Loaded {len(df)} labeled events from {data_path}")

    # Encode labels
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df["attack_type"])

    # Encode categorical features
    encoders = {}
    X = pd.DataFrame()
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        df[col] = df[col].astype(str)
        X[col] = le.fit_transform(df[col])
        encoders[col] = le

    if "hour" in df.columns:
        X["hour"] = df["hour"].fillna(0)
    else:
        X["hour"] = 0

    # Network features (optional — include if present in training data)
    for feat in NETWORK_FEATURES:
        if feat in df.columns:
            X[feat] = df[feat].fillna(0)

    # Scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    encoders["scaler"] = scaler
    encoders["label_encoder"] = label_encoder

    # Train/Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    # Model Selection
    if LGBM_AVAILABLE:
        print("🧠 Training LightGBM Classifier...")
        model = LGBMClassifier(
            n_estimators=200,
            learning_rate=0.05,
            num_leaves=31,
            random_state=42,
            verbose=-1
        )
    else:
        print("⚠️ LightGBM not available. Using Random Forest Classifier...")
        model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    # Metrics
    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred) * 100, 2),
        "precision": round(precision_score(y_test, y_pred, average='weighted', zero_division=0) * 100, 2),
        "recall": round(recall_score(y_test, y_pred, average='weighted', zero_division=0) * 100, 2),
        "f1_score": round(f1_score(y_test, y_pred, average='weighted', zero_division=0) * 100, 2),
        "classes": label_encoder.classes_.tolist(),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "classification_report": classification_report(
            y_test, y_pred,
            target_names=label_encoder.classes_,
            output_dict=True
        ),
        "model_type": "LightGBM" if LGBM_AVAILABLE else "RandomForest",
        "dataset_info": {
            "source": "CIC-IDS2017 compatible synthetic",
            "total_samples": len(df),
            "feature_count": X.shape[1],
            "network_features": [f for f in NETWORK_FEATURES if f in df.columns],
            "compatible_datasets": ["CIC-IDS2017", "UNSW-NB15", "KDD Cup 99"],
        },
        "training_date": datetime.now().isoformat(),
    }

    print(f"\n✅ Model Training Complete — {metrics['model_type']}")
    print(f"   Accuracy:  {metrics['accuracy']}%")
    print(f"   Precision: {metrics['precision']}%")
    print(f"   Recall:    {metrics['recall']}%")
    print(f"   F1-Score:  {metrics['f1_score']}%")

    # Save
    os.makedirs(os.path.join(_PROJECT_ROOT, "data"), exist_ok=True)
    joblib.dump(model, ML_MODEL_PATH)
    joblib.dump(encoders, ML_ENCODERS_PATH)
    with open(ML_METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"✅ Saved model → {ML_MODEL_PATH}")
    print(f"✅ Saved metrics → {ML_METRICS_PATH}")
    return metrics


def load_ml_engine():
    """Load the trained ML model and encoders. Returns (model, encoders) or (None, None)."""
    if os.path.exists(ML_MODEL_PATH) and os.path.exists(ML_ENCODERS_PATH):
        try:
            model = joblib.load(ML_MODEL_PATH)
            encoders = joblib.load(ML_ENCODERS_PATH)
            return model, encoders
        except Exception as e:
            print(f"⚠️ Error loading ML engine: {e}")
    return None, None


def predict_attack_type(row_df: pd.DataFrame, model, encoders) -> dict:
    """
    Predict attack type probabilities for a single row or batch.
    Returns dict with: predicted_class, confidence, probabilities
    """
    if model is None or encoders is None:
        return {"predicted_class": "unknown", "confidence": 0.0, "probabilities": {}}

    try:
        X = _build_features(row_df, encoders)
        label_encoder = encoders.get("label_encoder")

        proba = model.predict_proba(X)
        pred_idx = np.argmax(proba, axis=1)
        confidence = float(np.max(proba, axis=1)[0])

        if label_encoder:
            predicted_class = label_encoder.inverse_transform(pred_idx)[0]
            class_names = label_encoder.classes_
        else:
            predicted_class = str(pred_idx[0])
            class_names = [str(i) for i in range(proba.shape[1])]

        prob_dict = {cls: round(float(p), 4) for cls, p in zip(class_names, proba[0])}

        return {
            "predicted_class": predicted_class,
            "confidence": round(confidence * 100, 1),
            "probabilities": prob_dict
        }
    except Exception as e:
        return {"predicted_class": "unknown", "confidence": 0.0, "probabilities": {}, "error": str(e)}


def get_ml_metrics() -> dict:
    """Load saved metrics from disk."""
    if os.path.exists(ML_METRICS_PATH):
        with open(ML_METRICS_PATH, "r") as f:
            return json.load(f)
    return {}
