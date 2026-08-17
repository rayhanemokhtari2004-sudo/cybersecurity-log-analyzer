import sqlite3
from pathlib import Path

# Chemin de la base de données
DB_PATH = Path(__file__).parent / "security_logs.db"


def create_database():
    conn = sqlite3.connect(DB_PATH)
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

    # Table des alertes
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL,
            start_time TEXT,
            end_time TEXT,
            risk_score INTEGER
        )
    """)

    # Table des statistiques par IP
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_statistics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            total_attempts INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            successful_attempts INTEGER DEFAULT 0,
            risk_score INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()

    print("Database created successfully!")


if __name__ == "__main__":
    create_database()