"""
Explainable AI Module — SHAP-based feature importance for ML classifier.
Generates top feature contribution data for visualization in the frontend.
"""
import os
import json
import numpy as np
import pandas as pd

SHAP_CACHE_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'shap_values.json')

# Feature display names for the frontend
FEATURE_LABELS = {
    'hour': 'Hour of Day',
    'day_of_week': 'Day of Week',
    'is_weekend': 'Weekend Activity',
    'is_night': 'Night Activity',
    'role_encoded': 'User Role',
    'action_encoded': 'Action Type',
    'resource_encoded': 'Resource Type',
    'status_encoded': 'Request Status',
    'ip_oct1': 'IP Octet 1',
    'ip_oct2': 'IP Octet 2',
    'ip_oct3': 'IP Octet 3',
    'ip_oct4': 'IP Octet 4',
    'ip_is_private': 'Private IP Range',
    'login_failed': 'Login Failure',
    'suspicious_resource': 'Suspicious Resource',
    'off_hours': 'Off-Hours Activity',
}


def compute_shap_values(model, encoders, df: pd.DataFrame) -> dict:
    """
    Compute SHAP values to explain ML model predictions.
    Returns feature importance dict suitable for JSON serialization.
    Falls back to feature importance from model if SHAP unavailable.
    """
    try:
        import shap as shap_lib
        use_shap = True
    except ImportError:
        use_shap = False

    features = _prepare_features(df, encoders)
    if features.empty:
        return {"error": "No features to explain", "features": []}

    if use_shap and model is not None:
        try:
            explainer = shap_lib.TreeExplainer(model)
            shap_values = explainer.shap_values(features)

            # For multi-class, take the mean abs across classes
            if isinstance(shap_values, list):
                mean_abs = np.mean([np.abs(sv) for sv in shap_values], axis=0)
            else:
                mean_abs = np.abs(shap_values)

            feature_importance = np.mean(mean_abs, axis=0)
            result = _build_importance_dict(features.columns.tolist(), feature_importance, source="shap")
            _cache_shap(result)
            return result
        except Exception as e:
            pass  # Fall through to model importance

    # Fallback: use built-in feature_importances_ from LightGBM/RandomForest
    if model is not None and hasattr(model, 'feature_importances_'):
        try:
            importance = model.feature_importances_
            result = _build_importance_dict(features.columns.tolist(), importance, source="model_importance")
            _cache_shap(result)
            return result
        except Exception:
            pass

    # Last resort: return cached if available
    return load_cached_shap()


def _prepare_features(df: pd.DataFrame, encoders: dict) -> pd.DataFrame:
    """Apply same feature engineering as ml_engine.py."""
    try:
        from src.ml_engine import _engineer_features
        return _engineer_features(df, encoders, fit=False)
    except Exception:
        return pd.DataFrame()


def _build_importance_dict(feature_names: list, importance: np.ndarray, source: str) -> dict:
    """Build a sorted JSON-serializable dict of feature importances."""
    pairs = sorted(
        zip(feature_names, importance.tolist()),
        key=lambda x: abs(x[1]),
        reverse=True
    )
    return {
        "source": source,
        "features": [
            {
                "feature": FEATURE_LABELS.get(name, name.replace('_', ' ').title()),
                "raw_name": name,
                "importance": round(abs(val), 6),
                "direction": "positive" if val >= 0 else "negative",
            }
            for name, val in pairs[:15]  # top 15 features
        ],
        "generated_at": pd.Timestamp.utcnow().isoformat()
    }


def _cache_shap(result: dict):
    """Save SHAP values to disk cache."""
    try:
        os.makedirs(os.path.dirname(SHAP_CACHE_FILE), exist_ok=True)
        with open(SHAP_CACHE_FILE, 'w') as f:
            json.dump(result, f, indent=2)
    except Exception:
        pass


def load_cached_shap() -> dict:
    """Load cached SHAP values from disk."""
    try:
        if os.path.exists(SHAP_CACHE_FILE):
            with open(SHAP_CACHE_FILE, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return {"features": [], "source": "none", "message": "No SHAP data yet. Process some events first."}


def get_static_feature_importance() -> dict:
    """
    Return pre-defined typical feature importance for the ThreatPulse model.
    Used as fallback when no SHAP cache is available.
    """
    return {
        "source": "static_baseline",
        "features": [
            {"feature": "Login Failure", "raw_name": "login_failed", "importance": 0.31, "direction": "positive"},
            {"feature": "Night Activity", "raw_name": "is_night", "importance": 0.22, "direction": "positive"},
            {"feature": "Off-Hours Activity", "raw_name": "off_hours", "importance": 0.18, "direction": "positive"},
            {"feature": "Action Type", "raw_name": "action_encoded", "importance": 0.15, "direction": "positive"},
            {"feature": "Suspicious Resource", "raw_name": "suspicious_resource", "importance": 0.13, "direction": "positive"},
            {"feature": "Private IP Range", "raw_name": "ip_is_private", "importance": 0.11, "direction": "negative"},
            {"feature": "User Role", "raw_name": "role_encoded", "importance": 0.10, "direction": "positive"},
            {"feature": "Hour of Day", "raw_name": "hour", "importance": 0.09, "direction": "positive"},
            {"feature": "Request Status", "raw_name": "status_encoded", "importance": 0.08, "direction": "positive"},
            {"feature": "Weekend Activity", "raw_name": "is_weekend", "importance": 0.06, "direction": "positive"},
            {"feature": "Resource Type", "raw_name": "resource_encoded", "importance": 0.05, "direction": "positive"},
            {"feature": "Day of Week", "raw_name": "day_of_week", "importance": 0.04, "direction": "positive"},
        ],
        "generated_at": pd.Timestamp.utcnow().isoformat()
    }
