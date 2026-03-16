from utils.constants import WEIGHT_ANOMALY, WEIGHT_TIME, WEIGHT_ROLE, WEIGHT_RESOURCE

def calculate_risk_score(anomaly_score, time_risk, role_risk, resource_risk):
    """
    Weighted formula for final risk score.
    """
    final_score = (
        (anomaly_score * WEIGHT_ANOMALY) +
        (time_risk * WEIGHT_TIME) +
        (role_risk * WEIGHT_ROLE) +
        (resource_risk * WEIGHT_RESOURCE)
    )
    return min(100, max(0, final_score)) # Clamp between 0 and 100
