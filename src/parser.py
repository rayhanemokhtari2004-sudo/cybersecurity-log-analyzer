import re
import sqlite3

LOG_FILE = "data/auth.log"
DB_FILE = "database/security_logs.db"


def parse_log_line(line):
    pattern = (
        r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*?"
        r"(?:Accepted|Failed) password for "
        r"(?P<username>\S+) from "
        r"(?P<ip>\S+) port "
        r"(?P<port>\d+)"
    )

    match = re.search(pattern, line)

    if not match:
        return None

    status = "SUCCESS" if "Accepted password" in line else "FAILED"

    return {
        "timestamp": match.group("timestamp"),
        "username": match.group("username"),
        "ip": match.group("ip"),
        "port": int(match.group("port")),
        "status": status
    }


def read_logs():
    events = []

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            event = parse_log_line(line)

            if event:
                events.append(event)

    return events


def save_logs_to_database(logs):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

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
        """, (
            log["timestamp"],
            log["username"],
            log["ip"],
            log["port"],
            log["status"]
        ))

    conn.commit()
    conn.close()

    print(f"{len(logs)} logs saved to database.")


if __name__ == "__main__":
    logs = read_logs()

    for log in logs:
        print(log)

    save_logs_to_database(logs)