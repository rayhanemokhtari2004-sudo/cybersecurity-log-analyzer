from detector import detect_brute_force
from parser import read_logs


def generate_alerts(logs):
    alerts = detect_brute_force(logs)

    for alert in alerts:
        print("=" * 50)
        print("🚨 SECURITY ALERT")
        print("=" * 50)
        print(f"IP Address      : {alert['ip']}")
        print(f"Attack          : {alert['alert']}")
        print(f"Failed Attempts : {alert['failed_attempts']}")
        print(f"Start Time      : {alert['start_time']}")
        print(f"End Time        : {alert['end_time']}")
        print(f"Risk Score      : {alert['risk_score']}")
        print(f"Risk Level      : {alert['risk_level']}")
        print("=" * 50)


if __name__ == "__main__":
    logs = read_logs()
    generate_alerts(logs)