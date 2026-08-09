import sys
sys.path.insert(0, ".")

from src.agent.agent_store import AgentStore

store = AgentStore()
db_servers = store.list_mcp_connections()

for db_srv in db_servers:
    name = db_srv.get("name")
    cfg_dict = db_srv.get("config_json") or db_srv
    print(f"--- {name} ---")
    print("cfg_dict type:", type(cfg_dict))
    print("cfg_dict:", cfg_dict)
    print("has command:", isinstance(cfg_dict, dict) and cfg_dict.get("command"))
    print()
