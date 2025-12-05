import unittest
from unittest.mock import MagicMock, patch
from nis2_checker.scanner import Scanner

class TestScanner(unittest.TestCase):
    def setUp(self):
        self.config = {
            'timeout': 1,
            'checks': {
                'connectivity': True,
                'ssl_tls': True,
                'security_headers': True
            },
            'ssl': {'min_version': 'TLSv1.2'},
            'headers': {'required': ['HSTS']}
        }
        self.scanner = Scanner(self.config)

    @patch('nis2_checker.scanner.requests.get')
    def test_connectivity_pass(self, mock_get):
        mock_get.return_value.status_code = 200
        result = self.scanner.check_connectivity('http://example.com', None)
        self.assertEqual(result['status'], 'PASS')

    @patch('nis2_checker.scanner.requests.get')
    def test_connectivity_fail(self, mock_get):
        mock_get.side_effect = Exception("Connection error")
        result = self.scanner.check_connectivity('http://example.com', None)
        self.assertEqual(result['status'], 'FAIL')

    @patch('nis2_checker.scanner.requests.get')
    def test_headers_pass(self, mock_get):
        mock_get.return_value.headers = {'HSTS': 'max-age=31536000'}
        result = self.scanner.check_headers('http://example.com')
        self.assertEqual(result['status'], 'PASS')

    @patch('nis2_checker.scanner.requests.get')
    def test_headers_fail(self, mock_get):
        mock_get.return_value.headers = {}
        result = self.scanner.check_headers('http://example.com')
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('Missing headers', result['details'])

    def test_get_auth_none(self):
        target = {'url': 'http://example.com'}
        auth, headers = self.scanner._get_auth(target)
        self.assertIsNone(auth)
        self.assertIsNone(headers)

    @patch.dict('os.environ', {'TEST_USER': 'admin', 'TEST_PASS': 'secret'})
    def test_get_auth_basic(self):
        target = {'url': 'http://example.com', 'auth_id': 'TEST'}
        auth, headers = self.scanner._get_auth(target)
        self.assertEqual(auth, ('admin', 'secret'))
        self.assertIsNone(headers)

    def test_cidr_expansion(self):
        # Mock nmap_scanner
        self.scanner.nmap_scanner = MagicMock()
        self.scanner.nmap_scanner.discover_hosts.return_value = ['192.168.1.10', '192.168.1.11']
        self.scanner.nmap_scanner.scan_target.return_value = {} # Mock scan result for individual hosts

        # Mock check_connectivity to avoid network calls
        self.scanner.check_connectivity = MagicMock(return_value={'status': 'PASS', 'details': 'Mocked'})

        target = {'ip': '192.168.1.0/24', 'name': 'Test Net'}
        results = self.scanner.scan_target(target)

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['target'], '192.168.1.10')
        self.assertEqual(results[1]['target'], '192.168.1.11')
        self.assertEqual(results[0]['name'], 'Test Net - 192.168.1.10')

if __name__ == '__main__':
    unittest.main()
