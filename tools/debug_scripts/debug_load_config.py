import sys
sys.path.insert(0, ".")

from src.utils.config import load_config

config = load_config()
print("ticketing key exists:", "ticketing" in config)
print("ticketing value:", config.get("ticketing"))

ticket_verdicts = config.get("ticketing", {}).get("create_on_verdict", ["MALICIOUS", "SUSPICIOUS"])
print("ticket_verdicts:", ticket_verdicts)
print("UNKNOWN in list:", "UNKNOWN" in ticket_verdicts)

print()
print("llm model:", config.get("llm", {}).get("model"))
