import sqlite3
from pathlib import Path

db_path = Path.home() / ".blue-team-assistant" / "cache" / "agent.db"
con = sqlite3.connect(str(db_path))
cur = con.cursor()
cur.execute("SELECT id, name, config_json FROM mcp_connections ORDER BY name")
for row in cur.fetchall():
    print(row)
