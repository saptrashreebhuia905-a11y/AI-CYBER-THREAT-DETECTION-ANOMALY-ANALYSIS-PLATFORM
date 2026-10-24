def evaluate_rules(log: dict):
    risk_points = 0
    reasons = []
    if log.get("login_status") == "FAILED" and log.get("failed_attempts", 0) > 3:
        risk_points += 50
        reasons.append("Brute-Force Attack Pattern")
    if log.get("request_rate", 0) > 100:
        risk_points += 40
        reasons.append("High Request Rate / DDoS")
    return risk_points, reasons if reasons else ["Normal Behavior"]