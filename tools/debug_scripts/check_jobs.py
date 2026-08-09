import sqlite3
from pathlib import Path

db_path = Path.home() / ".blue-team-assistant" / "cache" / "analysis_jobs.db"
con = sqlite3.connect(str(db_path))
cur = con.cursor()
cur.execute("SELECT id, analysis_type, status, verdict, score, created_at FROM analysis_jobs ORDER BY created_at DESC LIMIT 10")
for row in cur.fetchall():
    print(row)
