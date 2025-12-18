from utils.constants import CRITICAL_RESOURCES, SENSITIVE_RESOURCES, OFFICE_HOURS_START, OFFICE_HOURS_END

def analyze_context(row):
    """
    Analyzes contextual risk factors.
    Returns individual risk components (0-100).
    """
    time_risk = 0
    role_risk = 0
    resource_risk = 0
    context_reasons = []

    # 1. Time Context
    # Higher risk if between 12 AM and 5 AM
    if 0 <= row['hour'] < 5:
        time_risk = 90
        context_reasons.append(f"Late Night Activity ({row['hour']}:00)")
    elif not (OFFICE_HOURS_START <= row['hour'] <= OFFICE_HOURS_END):
        time_risk = 50
        context_reasons.append("Outside Office Hours")
    else:
        time_risk = 10

    # 2. Resource Sensitivity
    if row['resource'] in CRITICAL_RESOURCES:
        resource_risk = 90
        context_reasons.append(f"Critical Resource Accessed: {row['resource']}")
    elif row['resource'] in SENSITIVE_RESOURCES:
        resource_risk = 60
        context_reasons.append(f"Sensitive Resource Accessed: {row['resource']}")
    else:
        resource_risk = 20

    # 3. User Role Context
    # If a normal user accesses critical resources -> High Risk
    if row['role'] == 'user' and row['resource'] in CRITICAL_RESOURCES:
        role_risk = 100
        context_reasons.append("Unauthorized Role Access (User -> Critical)")
    elif row['role'] == 'admin':
        # Admins are high trust but high impact if compromised
        role_risk = 50 
    else:
        role_risk = 20

    return time_risk, role_risk, resource_risk, context_reasons
