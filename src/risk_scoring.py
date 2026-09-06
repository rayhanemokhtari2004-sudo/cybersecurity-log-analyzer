def calculate_risk_score(failed_attempts):
    """Calculates risk score (0-100) and risk level (LOW, MEDIUM, HIGH, CRITICAL)

    Scoring matrix:
    - < 3 failed attempts  -> 10 (LOW) [0 attempts -> 0, LOW]
    - 3-4 failed attempts  -> 40 (MEDIUM)
    - 5-9 failed attempts  -> 70 (HIGH)
    - >= 10 failed attempts -> 100 (CRITICAL)
    """
    if failed_attempts <= 0:
        return 0, "LOW"
    elif failed_attempts < 3:
        return 10, "LOW"
    elif failed_attempts < 5:
        return 40, "MEDIUM"
    elif failed_attempts < 10:
        return 70, "HIGH"
    else:
        return 100, "CRITICAL"


if __name__ == "__main__":
    test_values = [0, 1, 3, 5, 10]
    for attempts in test_values:
        score, level = calculate_risk_score(attempts)
        print(f"Failed attempts: {attempts:2d} | Risk Score: {score:3d} | Risk Level: {level}")
