# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public

import os
import json
import unittest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from nis2scan.cli import cli, generate_index_page


class TestCliServe(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()
        self.directory = "test_reports_dir"
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)

    def tearDown(self):
        if os.path.exists(self.directory):
            for file in os.listdir(self.directory):
                os.remove(os.path.join(self.directory, file))
            os.rmdir(self.directory)

    def test_generate_index_page_escapes_xss(self):
        # Create a report file with XSS in project_name
        report_data = {
            "project_name": "</div><script>alert(1)</script>",
            "summary": {
                "total_score": 90,
                "stats": {"analyzed_hosts": 1}
            },
            "findings": []
        }
        report_path = os.path.join(self.directory, "nis2_report_20260624_120000.json")
        with open(report_path, "w") as f:
            json.dump(report_data, f)

        # Generate index.html
        generate_index_page(self.directory)

        # Read index.html and verify project name is escaped
        index_path = os.path.join(self.directory, "index.html")
        self.assertTrue(os.path.exists(index_path))
        with open(index_path, "r") as f:
            content = f.read()

        # It must be escaped
        self.assertNotIn("</div><script>alert(1)</script>", content)
        self.assertIn("&lt;/div&gt;&lt;script&gt;alert(1)&lt;/script&gt;", content)

    @patch("socketserver.TCPServer")
    @patch("nis2scan.watcher.start_watcher")
    def test_serve_default_host(self, mock_watcher, mock_server):
        # Verify default binding is 127.0.0.1 and not 0.0.0.0
        mock_instance = MagicMock()
        mock_server.return_value.__enter__.return_value = mock_instance

        # Run click command with custom port to avoid port conflict but actually TCPServer is mocked
        result = self.runner.invoke(cli, ["serve", "--port", "9999"])
        
        # TCPServer should have been instantiated with ("127.0.0.1", 9999)
        mock_server.assert_called_once()
        server_address = mock_server.call_args[0][0]
        self.assertEqual(server_address, ("127.0.0.1", 9999))
