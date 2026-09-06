import sys
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.risk_scoring import calculate_risk_score

DB_PATH = BASE_DIR / "database" / "security_logs.db"


def update_ip_statistics(db_path=None):
    """Calculates statistics per IP from logs table and updates ip_statistics."""
    target_db = Path(db_path) if db_path else DB_PATH
    
    conn = sqlite3.connect(target_db)
    cursor = conn.cursor()

    # Récupérer toutes les IP uniques
    cursor.execute("SELECT DISTINCT ip FROM logs")
    ips = cursor.fetchall()

    updated_count = 0
    for (ip,) in ips:
        # Nombre total de tentatives
        cursor.execute("SELECT COUNT(*) FROM logs WHERE ip = ?", (ip,))
        total_attempts = cursor.fetchone()[0]

        # Nombre d'échecs
        cursor.execute("SELECT COUNT(*) FROM logs WHERE ip = ? AND status = 'FAILED'", (ip,))
        failed_attempts = cursor.fetchone()[0]

        # Nombre de succès
        cursor.execute("SELECT COUNT(*) FROM logs WHERE ip = ? AND status = 'SUCCESS'", (ip,))
        successful_attempts = cursor.fetchone()[0]

        # Calcul du score et niveau de risque centralisé
        risk_score, risk_level = calculate_risk_score(failed_attempts)

        # Insérer ou mettre à jour les statistiques
        cursor.execute("""
            INSERT INTO ip_statistics (
                ip,
                total_attempts,
                failed_attempts,
                successful_attempts,
                risk_score,
                risk_level
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip)
            DO UPDATE SET
                total_attempts = excluded.total_attempts,
                failed_attempts = excluded.failed_attempts,
                successful_attempts = excluded.successful_attempts,
                risk_score = excluded.risk_score,
                risk_level = excluded.risk_level
        """, (
            ip,
            total_attempts,
            failed_attempts,
            successful_attempts,
            risk_score,
            risk_level
        ))
        updated_count += 1

    conn.commit()
    conn.close()
    return updated_count


if __name__ == "__main__":
    count = update_ip_statistics()
    print(f"Updated statistics for {count} IPs.")