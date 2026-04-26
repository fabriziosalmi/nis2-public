import unittest
from unittest.mock import patch, MagicMock
import os
import yaml
from click.testing import CliRunner
from nis2scan.cli import cli

class TestCliInit(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()
        self.output_file = "test_config_gen.yaml"

    def tearDown(self):
        if os.path.exists(self.output_file):
            os.remove(self.output_file)

    @patch('nis2scan.cli.Confirm.ask')
    @patch('nis2scan.cli.IntPrompt.ask')
    @patch('nis2scan.cli.Prompt.ask')
    def test_init_command_generates_config(self, mock_prompt, mock_int_prompt, mock_confirm):
        # Mock user inputs
        # Prompt.ask calls:
        # 1. Project Name
        # 2. IP Range (enter one)
        # 3. IP Range (empty to finish)
        # 4. Domain (enter one)
        # 5. Domain (empty to finish)
        mock_prompt.side_effect = [
            "Test Project", # Project Name
            "10.0.0.0/24",  # IP Range 1
            "",             # IP Range Finish
            "example.com",  # Domain 1
            ""              # Domain Finish
        ]

        # IntPrompt.ask calls:
        # 1. Timeout
        # 2. Concurrency
        # 3. Max Hosts
        mock_int_prompt.side_effect = [5, 10, 20]

        # Confirm.ask calls (Features):
        # 1. DNS
        # 2. Web
        # 3. Port
        # 4. Whois
        mock_confirm.side_effect = [True, False, True, False]

        result = self.runner.invoke(cli, ['init', '-o', self.output_file])

        # Check exit code
        self.assertEqual(result.exit_code, 0)
        self.assertIn(f"Configuration saved to {self.output_file}", result.output)

        # Verify file content
        self.assertTrue(os.path.exists(self.output_file))
        with open(self.output_file, 'r') as f:
            config = yaml.safe_load(f)

        self.assertEqual(config['project_name'], "Test Project")
        self.assertEqual(config['scan_timeout'], 5)
        self.assertEqual(config['concurrency'], 10)
        self.assertEqual(config['max_hosts'], 20)
        self.assertEqual(config['targets']['ip_ranges'], ["10.0.0.0/24"])
        self.assertEqual(config['targets']['domains'], ["example.com"])
        self.assertTrue(config['features']['dns_checks'])
        self.assertFalse(config['features']['web_checks'])
        self.assertTrue(config['features']['port_scan'])
        self.assertFalse(config['features']['whois_checks'])

if __name__ == '__main__':
    unittest.main()
