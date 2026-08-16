def calculate_risk_score(failed_attempts):
    if failed_attempts < 3:
        return 10, "LOW"

    elif failed_attempts < 5:
        return 40, "MEDIUM"

    elif failed_attempts < 10:
        return 70, "HIGH"

    else:
        return 100, "CRITICAL"


if __name__ == "__main__":

    test_values = [1, 3, 5, 10]

    for attempts in test_values:
        score, level = calculate_risk_score(attempts)

        print(
            f"Failed attempts: {attempts} | "
            f"Risk Score: {score} | "
            f"Risk Level: {level}"
        )