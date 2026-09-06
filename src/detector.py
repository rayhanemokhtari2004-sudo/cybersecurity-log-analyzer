import sys
from pathlib import Path
from datetime import datetime, timedelta

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.parser import read_logs
from src.risk_scoring import calculate_risk_score

WINDOW_MINUTES = 5
FAILED_THRESHOLD = 5


def parse_event_datetime(ts_str):
    """Safely converts log timestamp string to a datetime object avoiding year 1900 issue."""
    if isinstance(ts_str, datetime):
        return ts_str

    ts_clean = " ".join(ts_str.split())
    # Standard format check YYYY-MM-DD HH:MM:SS
    try:
        return datetime.strptime(ts_clean, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        pass

    # Syslog format check e.g., 'Aug 14 10:05:12'
    try:
        dt = datetime.strptime(ts_clean, "%b %d %H:%M:%S")
        # Replace year 1900 with current year
        return dt.replace(year=datetime.now().year)
    except ValueError:
        return datetime.now()


def detect_brute_force(logs):
    """Detects brute force attacks using a 5-minute sliding window algorithm.

    If an IP performs >= 5 FAILED attempts within any 5-minute window,
    a brute force alert is generated.
    """
    alerts = []
    if not logs:
        return alerts

    # Regrouper les tentatives FAILED par IP
    failed_by_ip = {}
    for log in logs:
        if log.get("status") == "FAILED":
            ip = log["ip"]
            dt = parse_event_datetime(log["timestamp"])
            log_copy = dict(log)
            log_copy["datetime"] = dt
            failed_by_ip.setdefault(ip, []).append(log_copy)

    # Analyse par IP
    for ip, attempts in failed_by_ip.items():
        # Trier chronologiquement
        attempts.sort(key=lambda x: x["datetime"])

        # Window detection
        triggered_windows = []
        for i, current_log in enumerate(attempts):
            start_time = current_log["datetime"]
            end_time = start_time + timedelta(minutes=WINDOW_MINUTES)

            window_attempts = [
                log for log in attempts[i:]
                if start_time <= log["datetime"] <= end_time
            ]

            count = len(window_attempts)
            if count >= FAILED_THRESHOLD:
                win_end = max(log["datetime"] for log in window_attempts)
                # Avoid duplicate windows for the same sequence
                win_key = (start_time.strftime("%Y-%m-%d %H:%M:%S"), win_end.strftime("%Y-%m-%d %H:%M:%S"))
                if win_key in triggered_windows:
                    continue
                triggered_windows.append(win_key)

                score, risk_level = calculate_risk_score(count)

                alerts.append({
                    "ip": ip,
                    "attack_type": "BRUTE FORCE DETECTED",
                    "failed_attempts": count,
                    "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "end_time": win_end.strftime("%Y-%m-%d %H:%M:%S"),
                    "risk_score": score,
                    "risk_level": risk_level
                })

    return alerts


if __name__ == "__main__":
    logs = read_logs()
    alerts = detect_brute_force(logs)
    print(f"Detected {len(alerts)} brute force alerts:")
    for alert in alerts:
        print(alert)