import unittest
from pathlib import Path
from src.rag.rag_knowledge_base import load_playbooks_from_yaml

class TestRagPlaybookLoader(unittest.TestCase):

    def setUp(self):
        """Set up the test environment."""
        self.playbooks_dir = Path(__file__).resolve().parents[1] / "data" / "rag_knowledge"

    def test_loader_finds_all_files(self):
        """Test that the loader finds all created YAML files."""
        documents = load_playbooks_from_yaml(self.playbooks_dir)
        # We created 5 YAML files
        self.assertGreater(len(documents), 4, "Should load documents from at least 5 files.")

    def test_loaded_documents_have_correct_schema(self):
        """Test that each loaded document has the required fields."""
        documents = load_playbooks_from_yaml(self.playbooks_dir)
        self.assertTrue(all("id" in d for d in documents))
        self.assertTrue(all("text" in d for d in documents))
        self.assertTrue(all("metadata" in d for d in documents))

    def test_metadata_contains_source(self):
        """Test that each document's metadata contains a 'source' field."""
        documents = load_playbooks_from_yaml(self.playbooks_dir)
        self.assertTrue(all("source" in d["metadata"] for d in documents))

    def test_total_document_count(self):
        """Test the total number of loaded entries."""
        documents = load_playbooks_from_yaml(self.playbooks_dir)
        # malicious_ioc: 1, suspicious_ioc: 1, domain_enrichment: 1, phishing: 1, mitre: 5
        expected_count = 9
        self.assertEqual(len(documents), expected_count)

if __name__ == '__main__':
    unittest.main()