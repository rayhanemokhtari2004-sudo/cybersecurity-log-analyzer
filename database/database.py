import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "security_logs.db"


def create_database(db_path=None):
    """Creates SQLite database tables if they do not exist."""
    target_db = Path(db_path) if db_path else DB_PATH
    target_db.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(target_db)
    cursor = conn.cursor()

    # Table des logs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER,
            status TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_logs_unique 
        ON logs (timestamp, username, ip, port, status)
    """)

    # Table des alertes
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_unique 
        ON alerts (ip, attack_type, start_time, end_time)
    """)

    # Table des statistiques par IP
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_statistics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            total_attempts INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            successful_attempts INTEGER DEFAULT 0,
            risk_score INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'LOW'
        )
    """)


    conn.commit()
    conn.close()
    print(f"Database verified/created at: {target_db}")


if __name__ == "__main__":
    create_database()