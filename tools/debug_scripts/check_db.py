import sqlite3
from pathlib import Path

db_path = Path.home() / ".blue-team-assistant" / "cache" / "agent.db"
print("DB path:", db_path, "| exists:", db_path.exists())

con = sqlite3.connect(str(db_path))
cur = con.cursor()

cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
print("Tables:", cur.fetchall())

cur.execute("SELECT * FROM mcp_connections")
cols = [d[0] for d in cur.description]
print("Columns:", cols)
for row in cur.fetchall():
    print(dict(zip(cols, row)))
