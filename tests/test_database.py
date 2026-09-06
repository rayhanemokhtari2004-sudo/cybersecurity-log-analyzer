import sys
import sqlite3
import tempfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from database.database import create_database
from src.parser import save_logs_to_database


def test_database_creation():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = Path(tmp.name)

    try:
        create_database(db_path)
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check table existence
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        assert "logs" in tables
        assert "alerts" in tables
        assert "ip_statistics" in tables
        conn.close()
    finally:
        if db_path.exists():
            db_path.unlink()


def test_database_idempotent_insertion():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = Path(tmp.name)

    try:
        create_database(db_path)

        logs = [
            {"timestamp": "Aug 14 10:00:01", "username": "admin", "ip": "192.168.1.10", "port": 50120, "status": "SUCCESS"},
            {"timestamp": "Aug 14 10:05:12", "username": "admin", "ip": "192.168.1.20", "port": 50121, "status": "FAILED"}
        ]

        # First save
        inserted1 = save_logs_to_database(logs, db_path)
        assert inserted1 == 2

        # Second save (same logs) -> should insert 0 new logs due to UNIQUE constraint
        inserted2 = save_logs_to_database(logs, db_path)
        assert inserted2 == 0

        # Verify total count in table is still 2
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs")
        total = cursor.fetchone()[0]
        assert total == 2
        conn.close()
    finally:
        if db_path.exists():
            db_path.unlink()
