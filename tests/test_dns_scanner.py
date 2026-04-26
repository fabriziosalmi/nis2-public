import unittest
from unittest.mock import MagicMock, patch
from nis2_checker.dns_scanner import DNSScanner
import dns.resolver

class TestDNSScanner(unittest.TestCase):
    def setUp(self):
        self.config = {
            'timeout': 1,
            'checks': {
                'email_security': True,
                'dns_security': True
            }
        }
        self.scanner = DNSScanner(self.config)

    @patch('dns.resolver.Resolver')
    def test_spf_pass(self, mock_resolver_cls):
        mock_resolver = mock_resolver_cls.return_value
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = '"v=spf1 include:_spf.google.com ~all"'
        mock_resolver.resolve.return_value = [mock_answer]
        self.scanner.resolver = mock_resolver

        result = self.scanner._check_spf("example.com")
        self.assertEqual(result['status'], "PASS")
        self.assertIn("SPF record found", result['details'])

    @patch('dns.resolver.Resolver')
    def test_spf_fail(self, mock_resolver_cls):
        mock_resolver = mock_resolver_cls.return_value
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer
        self.scanner.resolver = mock_resolver

        result = self.scanner._check_spf("example.com")
        self.assertEqual(result['status'], "FAIL")

    @patch('dns.resolver.Resolver')
    def test_dmarc_pass(self, mock_resolver_cls):
        mock_resolver = mock_resolver_cls.return_value
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = '"v=DMARC1; p=reject;"'
        mock_resolver.resolve.return_value = [mock_answer]
        self.scanner.resolver = mock_resolver

        result = self.scanner._check_dmarc("example.com")
        self.assertEqual(result['status'], "PASS")
        self.assertIn("DMARC record found", result['details'])

    @patch('dns.resolver.Resolver')
    def test_dnssec_pass(self, mock_resolver_cls):
        mock_resolver = mock_resolver_cls.return_value
        # Just ensure resolve doesn't raise exception
        mock_resolver.resolve.return_value = [] 
        self.scanner.resolver = mock_resolver

        result = self.scanner._check_dnssec("example.com")
        self.assertEqual(result['status'], "PASS")

    def test_extract_domain(self):
        self.assertEqual(self.scanner._extract_domain("https://example.com"), "example.com")
        self.assertEqual(self.scanner._extract_domain("http://sub.example.com:8080"), "sub.example.com")
        self.assertEqual(self.scanner._extract_domain("example.com"), "example.com")

if __name__ == '__main__':
    unittest.main()
