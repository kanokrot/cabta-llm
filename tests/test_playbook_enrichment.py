
import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from src.agent.playbook_engine import PlaybookEngine

class TestPlaybookEnrichment(unittest.TestCase):

    def setUp(self):
        """Set up a mock agent_loop and agent_store for the PlaybookEngine."""
        self.agent_loop = MagicMock()
        self.agent_loop.config = {'api_keys': {'virustotal': 'test_key'}}
        self.agent_store = MagicMock()
        self.engine = PlaybookEngine(self.agent_loop, self.agent_store)

    @patch('src.integrations.threat_intel.ThreatIntelligence.get_raw_virustotal_report', new_callable=AsyncMock)
    def test_enrichment_success(self, mock_get_raw_report):
        """Test successful context enrichment when flag is true."""
        # Mock the VT report
        mock_get_raw_report.return_value = {
            "data": {
                "relationships": {
                    "resolutions": {"data": [{"id": "enriched.domain.com", "type": "domain"}]},
                    "communicating_files": {"data": [{"id": "hash123", "type": "file"}]},
                    "downloaded_files": {"data": [{"id": "hash456", "type": "file"}]}
                }
            }
        }

        # Playbook with enrichment enabled
        playbook_def = {"auto_enrich_context": True}
        # Context with an IP but no domains/hashes
        initial_context = {"ip_addresses": ["8.8.8.8"]}

        # Run the enrichment
        final_context = asyncio.run(self.engine._enrich_context_if_needed(playbook_def, initial_context))

        # Assertions
        mock_get_raw_report.assert_called_once_with("8.8.8.8", "ipv4")
        self.assertIn("enriched.domain.com", final_context.get("domains", []))
        self.assertIn("hash123", final_context.get("file_hashes", []))
        self.assertIn("hash456", final_context.get("file_hashes", []))
        self.assertEqual(len(final_context.get("domains", [])), 1)
        self.assertEqual(len(final_context.get("file_hashes", [])), 2)

    @patch('src.integrations.threat_intel.ThreatIntelligence.get_raw_virustotal_report', new_callable=AsyncMock)
    def test_enrichment_timeout_fallback(self, mock_get_raw_report):
        """Test graceful fallback when enrichment times out."""
        # Mock a timeout
        mock_get_raw_report.side_effect = asyncio.TimeoutError

        playbook_def = {"auto_enrich_context": True}
        initial_context = {"ip_addresses": ["8.8.8.8"], "domains": [], "file_hashes": []}

        # Run the enrichment
        final_context = asyncio.run(self.engine._enrich_context_if_needed(playbook_def, initial_context))

        # Assertions
        mock_get_raw_report.assert_called_once_with("8.8.8.8", "ipv4")
        # Context should remain unchanged
        self.assertEqual(initial_context, final_context)
        self.assertEqual(len(final_context.get("domains", [])), 0)
        self.assertEqual(len(final_context.get("file_hashes", [])), 0)

    @patch('src.integrations.threat_intel.ThreatIntelligence.get_raw_virustotal_report', new_callable=AsyncMock)
    def test_enrichment_flag_false(self, mock_get_raw_report):
        """Test that no enrichment occurs when the flag is false."""
        # Playbook with enrichment disabled
        playbook_def = {"auto_enrich_context": False}
        initial_context = {"ip_addresses": ["8.8.8.8"]}

        # Run the enrichment
        final_context = asyncio.run(self.engine._enrich_context_if_needed(playbook_def, initial_context))

        # Assertions
        mock_get_raw_report.assert_not_called()
        self.assertEqual(initial_context, final_context)

    @patch('src.integrations.threat_intel.ThreatIntelligence.get_raw_virustotal_report', new_callable=AsyncMock)
    def test_enrichment_no_ips(self, mock_get_raw_report):
        """Test that no enrichment occurs if there are no IPs in context."""
        playbook_def = {"auto_enrich_context": True}
        initial_context = {"domains": ["example.com"]} # No IPs

        final_context = asyncio.run(self.engine._enrich_context_if_needed(playbook_def, initial_context))

        mock_get_raw_report.assert_not_called()
        self.assertEqual(initial_context, final_context)


if __name__ == '__main__':
    unittest.main()
