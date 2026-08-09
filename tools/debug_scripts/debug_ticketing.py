import sys
sys.path.insert(0, ".")
import yaml
from pathlib import Path

with open("config.yaml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

print("ticketing key exists:", "ticketing" in config)
print("ticketing value:", config.get("ticketing"))

ticket_verdicts = config.get("ticketing", {}).get("create_on_verdict", ["MALICIOUS", "SUSPICIOUS"])
print("ticket_verdicts:", ticket_verdicts)
print("'UNKNOWN' in ticket_verdicts:", "UNKNOWN" in ticket_verdicts)
