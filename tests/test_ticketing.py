
import unittest
import sqlite3
import os
import gc
import tempfile
from src.integrations.ticketing import initialize_database, create_incident_ticket, get_all_tickets

class TestTicketing(unittest.TestCase):

    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self._previous_db_path = os.environ.get('TICKETING_DB_PATH')
        self.db_path = os.path.join(self._temp_dir.name, 'tickets.db')
        os.environ['TICKETING_DB_PATH'] = self.db_path
        initialize_database()

    def tearDown(self):
        gc.collect()
        if self._previous_db_path is None:
            os.environ.pop('TICKETING_DB_PATH', None)
        else:
            os.environ['TICKETING_DB_PATH'] = self._previous_db_path
        self._temp_dir.cleanup()

    def test_01_initialize_database(self):
        self.assertTrue(os.path.exists(self.db_path))
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tickets'")
            self.assertIsNotNone(cursor.fetchone())

    def test_02_create_and_get_ticket(self):
        job_result = {
            'ioc': '8.8.8.8',
            'verdict': 'SUSPICIOUS',
            'summary': 'Test summary',
            'recommendations': ['rec1', 'rec2']
        }
        analysis_id = "test-analysis-123"

        ticket_id = create_incident_ticket(job_result, analysis_id, owner_id=101)
        self.assertIsNotNone(ticket_id)

        tickets = get_all_tickets()
        self.assertEqual(len(tickets), 1)
        ticket = tickets[0]

        self.assertEqual(ticket['ticket_id'], ticket_id)
        self.assertEqual(ticket['analysis_id'], analysis_id)
        self.assertEqual(ticket['owner_id'], 101)
        self.assertEqual(ticket['ioc'], '8.8.8.8')
        self.assertEqual(ticket['verdict'], 'SUSPICIOUS')
        self.assertEqual(ticket['status'], 'open')
        self.assertEqual(ticket['summary'], 'Test summary')
        import json
        self.assertEqual(json.loads(ticket['recommendations']), ['rec1', 'rec2'])

    def test_03_get_all_tickets_filters_by_owner_and_keeps_none_unscoped(self):
        result = {'ioc': '1.1.1.1', 'verdict': 'MALICIOUS'}
        own_id = create_incident_ticket(result, 'own-analysis', owner_id=101)
        other_id = create_incident_ticket(result, 'other-analysis', owner_id=202)
        legacy_id = create_incident_ticket(result, 'legacy-analysis')

        own_tickets = get_all_tickets(owner_id=101)
        all_tickets = get_all_tickets()

        self.assertEqual([ticket['ticket_id'] for ticket in own_tickets], [own_id])
        self.assertEqual(
            {ticket['ticket_id'] for ticket in all_tickets},
            {own_id, other_id, legacy_id},
        )
        self.assertIsNone(
            next(ticket for ticket in all_tickets if ticket['ticket_id'] == legacy_id)['owner_id']
        )

if __name__ == '__main__':
    unittest.main()
