import sqlite3
import json
from pathlib import Path

db_path = Path.home() / ".blue-team-assistant" / "cache" / "agent.db"
con = sqlite3.connect(str(db_path))
cur = con.cursor()

fixes = {
    "remnux_tools": {
        "name": "remnux_tools",
        "transport": "stdio",
        "command": "python",
        "args": ["-m", "src.mcp_servers.remnux_tools"],
        "url": None,
        "env": None,
        "description": "",
    },
    "threat_intel_tools": {
        "name": "threat_intel_tools",
        "transport": "stdio",
        "command": "python",
        "args": ["-m", "src.mcp_servers.threat_intel_tools"],
        "url": None,
        "env": None,
        "description": "",
    },
}

for name, cfg in fixes.items():
    cur.execute(
        "UPDATE mcp_connections SET config_json = ? WHERE name = ?",
        (json.dumps(cfg), name),
    )
    print(f"Updated {name}: {cur.rowcount} row(s)")

con.commit()

# Verify
cur.execute("SELECT name, config_json FROM mcp_connections")
for row in cur.fetchall():
    print(row)

con.close()
