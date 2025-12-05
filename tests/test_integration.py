import unittest
import threading
import time
import requests
from nis2_checker.scanner import Scanner
from simulation_server import start_server, PORT
import socket

class TestIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start simulation server in a separate thread
        cls.server_thread = threading.Thread(target=start_server, daemon=True)
        cls.server_thread.start()
        # Wait for server to start
        time.sleep(1)

    def setUp(self):
        self.base_url = f"http://localhost:{PORT}"
        self.config = {
            'timeout': 1,
            'checks': {
                'connectivity': True,
                'ssl_tls': False, # SSL not supported in simple http server mock
                'security_headers': True
            },
            'ssl': {'min_version': 'TLSv1.2'},
            'headers': {
                'required': ['Strict-Transport-Security', 'X-Content-Type-Options']
            }
        }
        self.scanner = Scanner(self.config)

    def test_compliant_target(self):
        target = {'url': f"{self.base_url}/compliant"}
        results = self.scanner.scan_target(target)
        result = results[0]
        
        if result['checks']['connectivity']['status'] != 'PASS':
            print(f"Connectivity Check Failed: {result['checks']['connectivity']['details']}")

        self.assertEqual(result['checks']['connectivity']['status'], 'PASS')
        self.assertEqual(result['checks']['security_headers']['status'], 'PASS')

    def test_non_compliant_target(self):
        target = {'url': f"{self.base_url}/non-compliant"}
        results = self.scanner.scan_target(target)
        result = results[0]
        
        self.assertEqual(result['checks']['connectivity']['status'], 'PASS')
        self.assertEqual(result['checks']['security_headers']['status'], 'FAIL')
        self.assertIn('Missing headers', result['checks']['security_headers']['details'])

if __name__ == '__main__':
    unittest.main()
