def recommend_action(risk_level):
    actions = {
        "Safe": {"action": "Ignore", "reason": "No malicious activity found."},
        "Suspicious": {"action": "Monitor", "reason": "Some indicators are flagged but not confirmed."},
        "Malicious": {"action": "Block", "reason": "Multiple sources confirm malicious behavior."}
    }
    return actions[risk_level]