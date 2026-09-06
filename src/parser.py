import re
import sqlite3
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "data" / "auth.log"
DB_FILE = BASE_DIR / "database" / "security_logs.db"


def parse_log_line(line):
    """Parses a single SSH auth.log line.

    Supports:
    - Accepted password for username from IP port PORT
    - Failed password for username from IP port PORT
    - Failed password for invalid user admin from IP port PORT -> username='admin'
    """
    pattern = (
        r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}).*?"
        r"(?P<action>Accepted|Failed) password for "
        r"(?:invalid user )?"
        r"(?P<username>\S+) from "
        r"(?P<ip>\S+) port "
        r"(?P<port>\d+)"
    )

    match = re.search(pattern, line)
    if not match:
        return None

    status = "SUCCESS" if match.group("action") == "Accepted" else "FAILED"
    ts_str = match.group("timestamp")
    
    # Format timestamp nicely (clean extra spaces if any)
    ts_clean = " ".join(ts_str.split())

    return {
        "timestamp": ts_clean,
        "username": match.group("username"),
        "ip": match.group("ip"),
        "port": int(match.group("port")),
        "status": status
    }


def read_logs(log_path=None):
    """Reads logs from auth.log file. Returns list of parsed event dicts."""
    target_path = Path(log_path) if log_path else LOG_FILE
    events = []

    if not target_path.exists():
        print(f"Warning: Log file not found at {target_path}")
        return events

    try:
        with open(target_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                event = parse_log_line(line)
                if event:
                    events.append(event)
    except Exception as e:
        print(f"Error reading log file {target_path}: {e}")

    return events


def save_logs_to_database(logs, db_path=None):
    """Saves parsed log events to SQLite database idempotently."""
    target_db = Path(db_path) if db_path else DB_FILE
    if not logs:
        return 0

    conn = sqlite3.connect(target_db)
    cursor = conn.cursor()

    inserted_count = 0
    for log in logs:
        cursor.execute("""
            INSERT INTO logs (
                timestamp,
                username,
                ip,
                port,
                status
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(timestamp, username, ip, port, status) DO NOTHING
        """, (
            log["timestamp"],
            log["username"],
            log["ip"],
            log["port"],
            log["status"]
        ))
        if cursor.rowcount > 0:
            inserted_count += 1

    conn.commit()
    conn.close()
    return inserted_count


if __name__ == "__main__":
    logs = read_logs()
    print(f"Parsed {len(logs)} log entries:")
    for log in logs:
        print(log)
    saved = save_logs_to_database(logs)
    print(f"Saved {saved} new logs to database.")