"""Tests for MR OSINT export helpers and provider registry."""
import json
import tempfile
import unittest
from pathlib import Path

from providers import USERNAME_PLATFORMS
from reporting import build_candidate_payload, write_csv, write_json


class ProviderTests(unittest.TestCase):
    def test_provider_templates_are_https(self):
        self.assertGreaterEqual(len(USERNAME_PLATFORMS), 10)
        for name, (template, _) in USERNAME_PLATFORMS.items():
            with self.subTest(provider=name):
                self.assertTrue(template.startswith("https://"))
                self.assertIn("{u}", template)


class ExportTests(unittest.TestCase):
    def test_candidate_json_and_csv_exports(self):
        payload = build_candidate_payload(
            "Consenting Applicant",
            {"profile_url": "https://github.com/example", "public_repos": 3, "name": "Example"},
            None,
            "https://example.org",
            (True, 200, "Portfolio"),
            [("https://example.org/cert", (True, 200, "Certificate"))],
        )
        with tempfile.TemporaryDirectory() as folder:
            json_path = Path(folder) / "candidate.json"
            csv_path = Path(folder) / "candidate.csv"
            write_json(payload, json_path)
            write_csv(payload, csv_path)
            self.assertEqual(json.loads(json_path.read_text())["candidate_name"], "Consenting Applicant")
            csv_text = csv_path.read_text()
            self.assertIn("github", csv_text)
            self.assertIn("certificate link", csv_text)


if __name__ == "__main__":
    unittest.main()
