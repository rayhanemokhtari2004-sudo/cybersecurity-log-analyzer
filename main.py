import sys
import sqlite3
from pathlib import Path

# Ensure project root is on Python path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from database.database import create_database, DB_PATH
from database.statistics import update_ip_statistics
from src.parser import read_logs, save_logs_to_database, LOG_FILE
from src.alerts import generate_alerts


def run_pipeline(log_path=None, db_path=None):
    """Executes the full Cyber Sentinel threat detection pipeline."""
    target_log = Path(log_path) if log_path else LOG_FILE
    target_db = Path(db_path) if db_path else DB_PATH

    print("==================================================")
    print("      CYBER SENTINEL — SECURITY PIPELINE")
    print("==================================================")

    # 1. Create/Verify Database
    print("[1/5] Verifying database schema...")
    create_database(target_db)

    # 2. Parse Logs
    print(f"[2/5] Parsing SSH logs from {target_log.name}...")
    logs = read_logs(target_log)
    print(f"      -> {len(logs)} log entries parsed.")

    # 3. Store Logs
    print("[3/5] Saving logs to database (idempotent)...")
    saved_logs = save_logs_to_database(logs, target_db)
    print(f"      -> {saved_logs} new log entries inserted.")

    # 4. Update IP Statistics
    print("[4/5] Updating IP statistics & calculating risk scores...")
    ip_count = update_ip_statistics(target_db)
    print(f"      -> Statistics updated for {ip_count} unique IPs.")

    # 5. Detect Brute Force & Generate Alerts
    print("[5/5] Running brute force detection & generating alerts...")
    alerts = generate_alerts(logs, target_db)

    # Summary calculations from DB
    conn = sqlite3.connect(target_db)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE status = 'FAILED'")
    failed_attempts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE status = 'SUCCESS'")
    successful_attempts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(DISTINCT ip) FROM logs")
    unique_ips = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts")
    alerts_generated = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM ip_statistics WHERE risk_level = 'CRITICAL'")
    critical_threats = cursor.fetchone()[0]

    conn.close()

    print("\n" + "=" * 50)
    print("Analysis completed successfully.")
    print("=" * 50)
    print(f"Logs processed      : {total_logs}")
    print(f"Failed attempts     : {failed_attempts}")
    print(f"Successful attempts : {successful_attempts}")
    print(f"Unique IPs          : {unique_ips}")
    print(f"Alerts generated    : {alerts_generated}")
    print(f"Critical threats    : {critical_threats}")
    print("=" * 50 + "\n")

    return {
        "total_logs": total_logs,
        "failed_attempts": failed_attempts,
        "successful_attempts": successful_attempts,
        "unique_ips": unique_ips,
        "alerts_generated": alerts_generated,
        "critical_threats": critical_threats
    }


if __name__ == "__main__":
    run_pipeline()
