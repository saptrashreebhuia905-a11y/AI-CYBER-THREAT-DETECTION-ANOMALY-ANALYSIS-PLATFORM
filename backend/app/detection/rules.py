def evaluate_rules(log: dict) -> tuple[int, list[str]]:
    risk_points = 0
    reasons = []

    if log.get("login_status") == "FAILED" and log.get("failed_attempts", 0) > 3:
        risk_points += 50
        reasons.append("Repeated failed login attempts")

    request_rate = log.get("request_rate", 0)
    if request_rate > 100:
        risk_points += 40
        reasons.append("High request rate")

    if log.get("failed_attempts", 0) > 10:
        risk_points += 20
        reasons.append("Very high failed-login count")

    return min(risk_points, 100), reasons
