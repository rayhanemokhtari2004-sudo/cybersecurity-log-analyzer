from datetime import datetime, timedelta
from parser import read_logs


WINDOW_MINUTES = 5
FAILED_THRESHOLD = 5


def detect_brute_force(logs):
    alerts = []

   
    failed_by_ip = {}

    for log in logs:
        if log["status"] == "FAILED":
            ip = log["ip"]

            if ip not in failed_by_ip:
                failed_by_ip[ip] = []

            failed_by_ip[ip].append(log)

    # Analyse de chaque IP
    for ip, attempts in failed_by_ip.items():

      
        for log in attempts:
            log["datetime"] = datetime.strptime(
                log["timestamp"],
                "%b %d %H:%M:%S"
            )

      
        for current_log in attempts:

            start_time = current_log["datetime"]
            end_time = start_time + timedelta(minutes=WINDOW_MINUTES)

            window_attempts = [
                log for log in attempts
                if start_time <= log["datetime"] <= end_time
            ]

          
            if len(window_attempts) >= FAILED_THRESHOLD:

                alerts.append({
                    "ip": ip,
                    "start_time": start_time,
                    "end_time": end_time,
                    "failed_attempts": len(window_attempts),
                    "alert": "BRUTE FORCE DETECTED"
                })

                break

    return alerts


if __name__ == "__main__":
    logs = read_logs()

    alerts = detect_brute_force(logs)

    for alert in alerts:
        print(alert)