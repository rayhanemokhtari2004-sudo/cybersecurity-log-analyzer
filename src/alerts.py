import sys
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.detector import detect_brute_force
from src.parser import read_logs

DB_PATH = BASE_DIR / "database" / "security_logs.db"


def save_alert(alert, db_path=None):
    """Enregistre une alerte dans la base de données de manière idempotente."""
    target_db = Path(db_path) if db_path else DB_PATH

    conn = sqlite3.connect(target_db)
    cursor = conn.cursor()

    attack_type = alert.get("attack_type") or alert.get("alert", "BRUTE FORCE DETECTED")
    start_time = str(alert["start_time"])
    end_time = str(alert["end_time"])

    cursor.execute("""
        INSERT INTO alerts (
            ip,
            attack_type,
            failed_attempts,
            start_time,
            end_time,
            risk_score,
            risk_level
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip, attack_type, start_time, end_time) DO NOTHING
    """, (
        alert["ip"],
        attack_type,
        alert["failed_attempts"],
        start_time,
        end_time,
        alert["risk_score"],
        alert["risk_level"]
    ))

    inserted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return inserted


def save_alerts_to_database(alerts, db_path=None):
    """Save a list of alert dicts into SQLite."""
    count = 0
    for alert in alerts:
        if save_alert(alert, db_path):
            count += 1
    return count


def generate_alerts(logs, db_path=None):
    """Runs brute force detection on logs and stores generated alerts in SQLite."""
    alerts = detect_brute_force(logs)
    saved_count = 0

    for alert in alerts:
        attack_type = alert.get("attack_type") or alert.get("alert", "BRUTE FORCE DETECTED")
        print("=" * 50)
        print("[!] SECURITY ALERT DETECTED")
        print("=" * 50)

        print(f"IP Address      : {alert['ip']}")
        print(f"Attack Type     : {attack_type}")
        print(f"Failed Attempts : {alert['failed_attempts']}")
        print(f"Start Time      : {alert['start_time']}")
        print(f"End Time        : {alert['end_time']}")
        print(f"Risk Score      : {alert['risk_score']}")
        print(f"Risk Level      : {alert['risk_level']}")
        print("=" * 50)

        if save_alert(alert, db_path):
            saved_count += 1
            print("Alert saved to database.\n")
        else:
            print("Alert already present in database.\n")

    return alerts


if __name__ == "__main__":
    logs = read_logs()
    generate_alerts(logs)