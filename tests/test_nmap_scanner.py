import unittest
from unittest.mock import MagicMock, patch
from nis2_checker.nmap_scanner import NmapScanner

class TestNmapScanner(unittest.TestCase):
    def setUp(self):
        self.config = {
            'nmap': {
                'enabled': True,
                'ports': {'ssh': 22, 'https': 443, 'http_mgmt': [80]},
                'checks': {
                    'ssh_password': True,
                    'tls_deprecated': True,
                    'http_cleartext': True
                }
            }
        }

    @patch('nis2_checker.nmap_scanner.shutil.which')
    @patch('nis2_checker.nmap_scanner.subprocess.run')
    def test_ssh_password_fail(self, mock_run, mock_which):
        mock_which.return_value = '/usr/bin/nmap'
        mock_run.return_value.stdout = "22/tcp open  ssh\n| ssh-auth-methods:\n|   Supported authentication methods:\n|     publickey\n|     password"
        
        scanner = NmapScanner(self.config)
        result = scanner.scan_target({'ip': '1.2.3.4'})
        
        self.assertEqual(result['ssh_auth']['status'], 'FAIL')
        self.assertIn('Password Authentication enabled', result['ssh_auth']['details'])

    @patch('nis2_checker.nmap_scanner.shutil.which')
    @patch('nis2_checker.nmap_scanner.subprocess.run')
    def test_tls_deprecated_fail(self, mock_run, mock_which):
        mock_which.return_value = '/usr/bin/nmap'
        # Mocking multiple calls? The scanner calls run_nmap multiple times.
        # We need to handle side_effect based on args or just mock the specific call we care about if we test methods individually.
        # Let's test _check_tls_infra directly for simplicity or setup side_effect.
        
        def side_effect(cmd, **kwargs):
            if 'ssl-enum-ciphers' in cmd:
                return MagicMock(stdout="443/tcp open  https\n| ssl-enum-ciphers:\n|   TLSv1.0:\n|     ciphers:\n|       TLS_RSA_WITH_AES_128_CBC_SHA")
            return MagicMock(stdout="")

        mock_run.side_effect = side_effect
        
        scanner = NmapScanner(self.config)
        result = scanner._check_tls_infra('1.2.3.4')
        
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('Deprecated TLS', result['details'])

    @patch('nis2_checker.nmap_scanner.shutil.which')
    def test_nmap_not_installed(self, mock_which):
        mock_which.return_value = None
        scanner = NmapScanner(self.config)
        result = scanner.scan_target({'ip': '1.2.3.4'})
        self.assertEqual(result, {})

if __name__ == '__main__':
    unittest.main()
