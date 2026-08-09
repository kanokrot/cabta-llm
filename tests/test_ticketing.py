
import unittest
import sqlite3
import os
import gc
from src.integrations.ticketing import initialize_database, create_incident_ticket, get_all_tickets

class TestTicketing(unittest.TestCase):

    def setUp(self):
        self.db_path = 'data/tickets/test_tickets.db'
        os.environ['TICKETING_DB_PATH'] = self.db_path
        initialize_database()

    def tearDown(self):
        gc.collect()
        os.remove(self.db_path)

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

        ticket_id = create_incident_ticket(job_result, analysis_id)
        self.assertIsNotNone(ticket_id)

        tickets = get_all_tickets()
        self.assertEqual(len(tickets), 1)
        ticket = tickets[0]

        self.assertEqual(ticket['ticket_id'], ticket_id)
        self.assertEqual(ticket['analysis_id'], analysis_id)
        self.assertEqual(ticket['ioc'], '8.8.8.8')
        self.assertEqual(ticket['verdict'], 'SUSPICIOUS')
        self.assertEqual(ticket['status'], 'open')
        self.assertEqual(ticket['summary'], 'Test summary')
        import json
        self.assertEqual(json.loads(ticket['recommendations']), ['rec1', 'rec2'])

if __name__ == '__main__':
    unittest.main()

