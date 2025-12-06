import unittest
import threading
import time
import requests
from nis2_checker.scanner_logic import ScannerLogic
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
                'security_headers': True,
                'whois_check': False, # Disable external checks
                'dns_checks': False     # Disable external checks
            },
            'ssl': {'min_version': 'TLSv1.2'},
            'headers': {
                'required': ['Strict-Transport-Security', 'X-Content-Type-Options']
            },
            # Add required sections for ScannerLogic init
            'nmap': {}, 
            'dns': {}, 
            'whois': {'enabled': False}, 
            'content': {}
        }
        self.scanner = ScannerLogic(self.config)

    def test_compliant_target(self):
        target = {'url': f"{self.base_url}/compliant"}
        results = self.scanner.scan_target(target)
        result = results[0]
        
        # Convert list of checks to dict for easier testing
        checks = {c.check_id: c for c in result.results}

        if checks['connectivity'].status != 'PASS':
            print(f"Connectivity Check Failed: {checks['connectivity'].details}")

        self.assertEqual(checks['connectivity'].status, 'PASS')
        self.assertEqual(checks['security_headers'].status, 'PASS')

    def test_non_compliant_target(self):
        target = {'url': f"{self.base_url}/non-compliant"}
        results = self.scanner.scan_target(target)
        result = results[0]
        
        checks = {c.check_id: c for c in result.results}
        
        self.assertEqual(checks['connectivity'].status, 'PASS')
        self.assertEqual(checks['security_headers'].status, 'FAIL')
        self.assertIn('Missing headers', checks['security_headers'].details)

if __name__ == '__main__':
    unittest.main()
