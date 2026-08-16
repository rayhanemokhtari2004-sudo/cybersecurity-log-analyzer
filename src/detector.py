from datetime import datetime, timedelta
from parser import read_logs
from risk_scoring import calculate_risk_score


WINDOW_MINUTES = 5
FAILED_THRESHOLD = 5


def detect_brute_force(logs):
    alerts = []

    # Regrouper les tentatives FAILED par IP
    failed_by_ip = {}

    for log in logs:
        if log["status"] == "FAILED":
            ip = log["ip"]

            if ip not in failed_by_ip:
                failed_by_ip[ip] = []

            failed_by_ip[ip].append(log)

    # Analyse de chaque IP
    for ip, attempts in failed_by_ip.items():

        # Convertir les timestamps en datetime
        for log in attempts:
            log["datetime"] = datetime.strptime(
                log["timestamp"],
                "%b %d %H:%M:%S"
            )

        # Sliding Window
        for current_log in attempts:

            start_time = current_log["datetime"]
            end_time = start_time + timedelta(minutes=WINDOW_MINUTES)

            window_attempts = [
                log
                for log in attempts
                if start_time <= log["datetime"] <= end_time
            ]

            # Détection Brute Force
            if len(window_attempts) >= FAILED_THRESHOLD:

                # Calcul du Risk Score
                score, risk_level = calculate_risk_score(
                    len(window_attempts)
                )

                alerts.append({
                    "ip": ip,
                    "start_time": start_time,
                    "end_time": end_time,
                    "failed_attempts": len(window_attempts),
                    "alert": "BRUTE FORCE DETECTED",
                    "risk_score": score,
                    "risk_level": risk_level
                })

                break

    return alerts


if __name__ == "__main__":
    logs = read_logs()

    alerts = detect_brute_force(logs)

    for alert in alerts:
        print(alert)