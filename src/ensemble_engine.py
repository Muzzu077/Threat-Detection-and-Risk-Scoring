"""
TrustFlow — Ensemble ML Engine
Trains an XGBoost classifier alongside the existing LightGBM model and
combines their predictions via averaged probabilities. Saves a separate
artifact (`ml_xgb_model.pkl`) so the LightGBM artifact stays untouched.

Inference path:
    1. Load both models if present.
    2. predict_ensemble(row_df) → averages probabilities, returns the same
       shape as ml_engine.predict_attack_type plus a per-model breakdown.

If only one model exists, the engine gracefully degrades to the available one.
"""
import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime

from src.ml_engine import (
    _build_features, ML_MODEL_PATH, ML_ENCODERS_PATH,
    load_ml_engine,
)

try:
    from xgboost import XGBClassifier
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ML_XGB_MODEL_PATH = os.path.join(_PROJECT_ROOT, "data", "ml_xgb_model.pkl")
ML_ENSEMBLE_METRICS = os.path.join(_PROJECT_ROOT, "data", "ml_ensemble_metrics.json")


def train_xgboost(data_path: str = None) -> dict:
    """Train XGBoost on the same labeled data the LightGBM was trained on."""
    if not XGB_AVAILABLE:
        raise RuntimeError("xgboost not installed. Add `xgboost` to requirements.txt and rebuild.")

    if data_path is None:
        data_path = os.path.join(_PROJECT_ROOT, "data", "labeled_logs.csv")
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Labeled dataset not found at {data_path}")

    from sklearn.preprocessing import LabelEncoder, StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
    from src.ml_engine import CATEGORICAL_COLS, NETWORK_FEATURES

    df = pd.read_csv(data_path)
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df["attack_type"])

    encoders = {}
    X = pd.DataFrame()
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        df[col] = df[col].astype(str)
        X[col] = le.fit_transform(df[col])
        encoders[col] = le
    X["hour"] = df["hour"].fillna(0) if "hour" in df.columns else 0
    for feat in NETWORK_FEATURES:
        if feat in df.columns:
            X[feat] = df[feat].fillna(0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    encoders["scaler"] = scaler
    encoders["label_encoder"] = label_encoder

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    print("🌲 Training XGBoost Classifier...")
    model = XGBClassifier(
        n_estimators=200, learning_rate=0.05, max_depth=6,
        objective="multi:softprob", eval_metric="mlogloss",
        random_state=42, n_jobs=-1, verbosity=0,
    )
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    metrics = {
        "model_type": "XGBoost",
        "accuracy":   round(accuracy_score(y_test, y_pred) * 100, 2),
        "precision":  round(precision_score(y_test, y_pred, average="weighted", zero_division=0) * 100, 2),
        "recall":     round(recall_score(y_test, y_pred, average="weighted", zero_division=0) * 100, 2),
        "f1_score":   round(f1_score(y_test, y_pred, average="weighted", zero_division=0) * 100, 2),
        "classes":    label_encoder.classes_.tolist(),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "training_date": datetime.utcnow().isoformat(),
    }

    joblib.dump(model, ML_XGB_MODEL_PATH)
    global _XGB_MODEL_CACHE
    _XGB_MODEL_CACHE = None

    print(f"✅ XGBoost saved → {ML_XGB_MODEL_PATH} — accuracy {metrics['accuracy']}%")
    return metrics


_XGB_MODEL_CACHE = None


def load_xgboost():
    """Load XGBoost model from disk. Returns model or None. Cached in memory."""
    global _XGB_MODEL_CACHE
    if _XGB_MODEL_CACHE is not None:
        return _XGB_MODEL_CACHE

    if os.path.exists(ML_XGB_MODEL_PATH):
        try:
            _XGB_MODEL_CACHE = joblib.load(ML_XGB_MODEL_PATH)
            return _XGB_MODEL_CACHE
        except Exception as e:
            print(f"⚠️ Failed to load XGBoost: {e}")
    return None


def _model_proba(model, X):
    """Get probability array from a model that exposes predict_proba."""
    return model.predict_proba(X)


def predict_ensemble(row_df: pd.DataFrame) -> dict:
    """
    Run both LGBM and XGB on the same row, return averaged probabilities.

    Returns:
        {
          predicted_class, confidence, probabilities,
          per_model: {lgbm: {class, conf}, xgb: {class, conf}},
          ensemble_size: int (1 or 2)
        }
    """
    lgbm, encoders = load_ml_engine()
    xgb = load_xgboost()

    if lgbm is None and xgb is None:
        return {"predicted_class": "unknown", "confidence": 0.0, "probabilities": {}, "ensemble_size": 0}

    if encoders is None:
        # XGB was saved without a separate encoder file; we rely on lgbm's encoders.
        return {"predicted_class": "unknown", "confidence": 0.0, "probabilities": {}, "ensemble_size": 0,
                "error": "encoders missing — train LightGBM first"}

    X = _build_features(row_df, encoders)
    label_encoder = encoders.get("label_encoder")
    class_names = label_encoder.classes_.tolist() if label_encoder else []

    probas, per_model = [], {}

    if lgbm is not None:
        try:
            p = _model_proba(lgbm, X)
            probas.append(p)
            idx = int(np.argmax(p[0]))
            per_model["lgbm"] = {
                "class": class_names[idx] if idx < len(class_names) else str(idx),
                "confidence": round(float(p[0][idx]) * 100, 1),
            }
        except Exception as e:
            per_model["lgbm"] = {"error": str(e)}

    if xgb is not None:
        try:
            p = _model_proba(xgb, X)
            probas.append(p)
            idx = int(np.argmax(p[0]))
            per_model["xgb"] = {
                "class": class_names[idx] if idx < len(class_names) else str(idx),
                "confidence": round(float(p[0][idx]) * 100, 1),
            }
        except Exception as e:
            per_model["xgb"] = {"error": str(e)}

    if not probas:
        return {"predicted_class": "unknown", "confidence": 0.0, "probabilities": {}, "ensemble_size": 0,
                "per_model": per_model}

    avg = np.mean(probas, axis=0)
    pred_idx = int(np.argmax(avg[0]))
    confidence = float(avg[0][pred_idx])
    predicted_class = class_names[pred_idx] if pred_idx < len(class_names) else str(pred_idx)
    prob_dict = {cls: round(float(p), 4) for cls, p in zip(class_names, avg[0])}

    return {
        "predicted_class": predicted_class,
        "confidence": round(confidence * 100, 1),
        "probabilities": prob_dict,
        "per_model": per_model,
        "ensemble_size": len(probas),
    }


def get_ensemble_metrics() -> dict:
    """Load saved ensemble comparison metrics."""
    if os.path.exists(ML_ENSEMBLE_METRICS):
        with open(ML_ENSEMBLE_METRICS) as f:
            return json.load(f)
    return {}


def compute_and_save_ensemble_metrics() -> dict:
    """
    Train (if needed) and compare LGBM, XGB, and the averaged ensemble on a held-out split.
    Saves to ml_ensemble_metrics.json so /api/ml/ensemble can serve it cheaply.
    """
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, f1_score
    from src.ml_engine import CATEGORICAL_COLS, NETWORK_FEATURES

    data_path = os.path.join(_PROJECT_ROOT, "data", "labeled_logs.csv")
    if not os.path.exists(data_path):
        return {"error": "no labeled data"}

    df = pd.read_csv(data_path)

    # Use the existing trained encoders/scaler so both models score on the same feature space
    if not (os.path.exists(ML_MODEL_PATH) and os.path.exists(ML_ENCODERS_PATH)):
        return {"error": "lgbm not trained"}
    encoders = joblib.load(ML_ENCODERS_PATH)
    label_encoder = encoders["label_encoder"]
    scaler = encoders["scaler"]

    y = label_encoder.transform(df["attack_type"])

    X = pd.DataFrame()
    for col in CATEGORICAL_COLS:
        le = encoders.get(col)
        df[col] = df[col].astype(str)
        le_map = dict(zip(le.classes_, le.transform(le.classes_)))
        X[col] = df[col].map(le_map).fillna(0)
    X["hour"] = df["hour"].fillna(0) if "hour" in df.columns else 0
    for feat in NETWORK_FEATURES:
        if feat in df.columns:
            X[feat] = df[feat].fillna(0)
    X_scaled = scaler.transform(X)

    _, X_test, _, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42, stratify=y)

    lgbm = joblib.load(ML_MODEL_PATH)
    xgb = load_xgboost()

    out = {"per_model": {}, "evaluated_at": datetime.utcnow().isoformat()}

    lgbm_proba = lgbm.predict_proba(X_test)
    lgbm_pred = np.argmax(lgbm_proba, axis=1)
    out["per_model"]["lgbm"] = {
        "accuracy": round(accuracy_score(y_test, lgbm_pred) * 100, 2),
        "f1":       round(f1_score(y_test, lgbm_pred, average="weighted", zero_division=0) * 100, 2),
    }

    if xgb is not None:
        xgb_proba = xgb.predict_proba(X_test)
        xgb_pred = np.argmax(xgb_proba, axis=1)
        out["per_model"]["xgb"] = {
            "accuracy": round(accuracy_score(y_test, xgb_pred) * 100, 2),
            "f1":       round(f1_score(y_test, xgb_pred, average="weighted", zero_division=0) * 100, 2),
        }
        ens_proba = (lgbm_proba + xgb_proba) / 2.0
        ens_pred = np.argmax(ens_proba, axis=1)
        out["per_model"]["ensemble"] = {
            "accuracy": round(accuracy_score(y_test, ens_pred) * 100, 2),
            "f1":       round(f1_score(y_test, ens_pred, average="weighted", zero_division=0) * 100, 2),
            "members":  ["lgbm", "xgb"],
            "method":   "averaged_probabilities",
        }
    else:
        out["per_model"]["ensemble"] = {"error": "xgb not trained — only lgbm available"}

    out["classes"] = label_encoder.classes_.tolist()
    out["test_set_size"] = int(len(y_test))

    os.makedirs(os.path.dirname(ML_ENSEMBLE_METRICS), exist_ok=True)
    with open(ML_ENSEMBLE_METRICS, "w") as f:
        json.dump(out, f, indent=2)

    return out
