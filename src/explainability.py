def generate_explanation(row, anomaly_score, context_reasons, rule_reasons):
    """
    Constructs a textual explanation for the risk score.
    """
    explanations = []
    
    # 1. Anomaly Explanation
    if anomaly_score > 70:
        explanations.append(f"• Highly anomalous behavior pattern detected (Score: {anomaly_score:.1f})")
    elif anomaly_score > 40:
        explanations.append(f"• Moderately anomalous behavior detected (Score: {anomaly_score:.1f})")
        
    # 2. Rule Violations
    for reason in rule_reasons:
        explanations.append(f"• Rule Violation: {reason}")
        
    # 3. Contextual Reasons
    for reason in context_reasons:
        explanations.append(f"• Context: {reason}")
        
    if not explanations:
        return "Normal activity."
        
    return "\n".join(explanations)
