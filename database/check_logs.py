import sqlite3
from pathlib import Path

# Chemin vers la base de données
DB_PATH = Path(__file__).parent / "security_logs.db"

# Connexion à la base
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# ==============================
# AFFICHER LES LOGS
# ==============================

print("=" * 60)
print("LOGS DANS LA BASE")
print("=" * 60)

cursor.execute("SELECT * FROM logs")

logs = cursor.fetchall()

if logs:
    for log in logs:
        print(log)
else:
    print("Aucun log trouvé.")

# ==============================
# AFFICHER LES ALERTES
# ==============================

print("\n" + "=" * 60)
print("ALERTES DANS LA BASE")
print("=" * 60)

cursor.execute("SELECT * FROM alerts")

alerts = cursor.fetchall()

if alerts:
    for alert in alerts:
        print(alert)
else:
    print("Aucune alerte trouvée.")

# ==============================
# FERMER LA CONNEXION
# ==============================

conn.close()