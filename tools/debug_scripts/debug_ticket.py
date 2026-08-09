import sys
sys.path.insert(0, ".")

from src.integrations.ticketing import create_incident_ticket, _get_db_path

print("DB path:", _get_db_path())

fake_result = {
    "ioc": "vulnweb.com",
    "verdict": "UNKNOWN",
    "recommendations": ["test rec 1", "test rec 2"],
}

ticket_id = create_incident_ticket(fake_result, "test-analysis-123")
print("Ticket ID returned:", ticket_id)
