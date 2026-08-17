import sqlite3

conn = sqlite3.connect("database/security_logs.db")
cursor = conn.cursor()

cursor.execute("""
    SELECT id, timestamp, username, ip, port, status
    FROM logs
""")

logs = cursor.fetchall()

print("Logs dans la base :")

for log in logs:
    print(log)

conn.close()