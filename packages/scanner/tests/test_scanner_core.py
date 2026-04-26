import asyncio
import unittest
from unittest.mock import MagicMock, patch
from nis2scan.scanner import Scanner, ScanResult
from nis2scan.config import Config, Targets

class TestScannerCore(unittest.TestCase):
    def setUp(self):
        self.config = Config(
            targets=Targets(ip_ranges=["192.168.1.1"]), 
            features={"port_scan": True, "web_checks": True}
        )
        self.scanner = Scanner(self.config)

    @patch('nis2scan.scanner.Scanner.check_port')
    @patch('nis2scan.scanner.Scanner.check_http')
    def test_scan_ip_http_failure_marks_host_down(self, mock_check_http, mock_check_port):
        """
        Test that if a port is open via TCP but fails HTTP check (e.g. connection reset),
        it is removed from open_ports. If no other ports are open, host is marked down.
        """
        # Setup: Port 80 appears open (TCP handshake works)
        mock_check_port.side_effect = lambda ip, port: port == 80
        
        # Setup: HTTP check fails (returns error dict)
        mock_check_http.return_value = {'error': 'Connection refused'}

        # Run scan_ip
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(self.scanner.scan_ip("192.168.1.1", "192.168.1.1"))
        loop.close()

        # Assertions
        # Port 80 should be removed because HTTP check failed
        self.assertNotIn(80, result.open_ports)
        # Host should be marked as not alive if no other ports are open
        self.assertFalse(result.is_alive)

    @patch('nis2scan.scanner.Scanner.check_port')
    @patch('nis2scan.scanner.Scanner.check_http')
    def test_scan_ip_http_success_marks_host_up(self, mock_check_http, mock_check_port):
        """Test that a successful HTTP check keeps the port and marks host up."""
        # Setup: Port 80 appears open
        mock_check_port.side_effect = lambda ip, port: port == 80
        
        # Setup: HTTP check succeeds
        mock_check_http.return_value = {'status': 200}

        # Run scan_ip
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(self.scanner.scan_ip("192.168.1.1", "192.168.1.1"))
        loop.close()

        # Assertions
        self.assertIn(80, result.open_ports)
        self.assertTrue(result.is_alive)

if __name__ == '__main__':
    unittest.main()
