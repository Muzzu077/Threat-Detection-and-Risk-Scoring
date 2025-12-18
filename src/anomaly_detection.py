import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import joblib

def train_anomaly_model(df):
    """
    Trains an Isolation Forest model on the log data.
    """
    # Feature Engineering for ML
    # We encode categorical variables: user, role, action, resource
    # IP is tricky, maybe just frequency or unique count, but for simple proto use label encoding
    
    le_user = LabelEncoder()
    le_role = LabelEncoder()
    le_action = LabelEncoder()
    le_resource = LabelEncoder()
    
    # Create a copy to avoid setting with copy warning issues on original df
    X = df[['hour']].copy() # Hour is numeric
    
    X['user_enc'] = le_user.fit_transform(df['user'])
    X['role_enc'] = le_role.fit_transform(df['role'])
    X['action_enc'] = le_action.fit_transform(df['action'])
    X['resource_enc'] = le_resource.fit_transform(df['resource'])
    
    # Isolation Forest
    # contamination is the estimate of outlier proportion
    clf = IsolationForest(contamination=0.05, random_state=42)
    clf.fit(X)
    
    return clf, (le_user, le_role, le_action, le_resource)

def detect_anomalies(df, model, encoders):
    """
    Predicts anomalies and calculates scores.
    """
    le_user, le_role, le_action, le_resource = encoders
    
    X = df[['hour']].copy()
    
    # Handle new categories safely (for demo, we might just clip or map to -1/0)
    # Ideally use a robust encoder, but here we try/except or map
    
    def safe_transform(le, col_data):
        # Extend classes if unseen (hacky for demo but prevents crash)
        # In prod, we'd handle unseen differently
        # For simplicity, we stick to known classes or map to 0
        known = set(le.classes_)
        return col_data.apply(lambda x: le.transform([x])[0] if x in known else 0)

    X['user_enc'] = safe_transform(le_user, df['user'])
    X['role_enc'] = safe_transform(le_role, df['role'])
    X['action_enc'] = safe_transform(le_action, df['action'])
    X['resource_enc'] = safe_transform(le_resource, df['resource'])
    
    # Decision function: lower is more anomalous. Range roughly -0.5 to 0.5
    # We want a 0-100 score where 100 is highly anomalous
    scores = model.decision_function(X)
    
    # Normalize scores: decision_function yields positive for inliers, negative for outliers
    # We invert this: smaller score = more anomalous.
    # Map roughly [-0.5, 0.5] to [100, 0]
    
    # Simple MinMax scaling or logistic could work.
    # Heuristic: 
    # score < 0 -> anomaly.
    
    anomaly_scores = 100 * (0.5 - scores) # rough scaling
    anomaly_scores = anomaly_scores.clip(0, 100) # clip to 0-100
    
    return anomaly_scores

def check_rule_based_anomalies(row, office_start=9, office_end=17):
    """
    Returns a score boost for specific rule violations.
    """
    score = 0
    reasons = []
    
    # Rules
    # 1. Unusual Time
    if not (office_start <= row['hour'] <= office_end):
        score += 20
        reasons.append("Outside Office Hours")
        
    # 2. Failed Login
    if row['action'] == 'login' and row['status'] == 'failed':
        score += 30
        reasons.append("Failed Login Attempt")

    # 3. Critical Threat Patterns (Keywords)
    action_lower = str(row['action']).lower()
    critical_keywords = ['sql', 'injection', 'brute', 'force', 'malware', 'ddos', 'exfiltration', 'shutdown', 'upload']
    
    for keyword in critical_keywords:
        if keyword in action_lower:
            score += 100
            reasons.append(f"Critical Action Detected: {keyword.upper()}")
            break # One critical match is enough for max score
        
    return score, reasons

def save_model(model, encoders, filepath='model.pkl'):
    joblib.dump((model, encoders), filepath)

def load_model(filepath='model.pkl'):
    try:
        return joblib.load(filepath)
    except:
        return None, None

