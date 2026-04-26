import unittest
from unittest.mock import MagicMock, patch
import ipaddress
import dns.resolver

# Helper function to test the logic used in scanner.py
def should_check_legal(host_header):
    should_check = False
    try:
        # Check if IP
        ipaddress.ip_address(host_header)
    except ValueError:
        # Not an IP, assume domain
        parts = host_header.split('.')
        if host_header.startswith('www.'):
            should_check = True
        elif len(parts) == 2:
            # e.g. example.com
            should_check = True
        elif len(parts) == 3 and len(parts[-1]) == 2 and len(parts[-2]) <= 3:
            # Heuristic for co.uk, com.it, etc.
            should_check = True
    return should_check

class TestScannerLogic(unittest.TestCase):

    def test_piva_check_logic(self):
        # Should check
        self.assertTrue(should_check_legal("example.com"))
        self.assertTrue(should_check_legal("www.example.com"))
        self.assertTrue(should_check_legal("google.co.uk"))
        self.assertTrue(should_check_legal("example.com.it")) # 3 parts, last is 2 chars, 2nd last is 3 chars

        # Should NOT check
        self.assertFalse(should_check_legal("192.168.1.1"))
        self.assertFalse(should_check_legal("mail.example.com"))
        self.assertFalse(should_check_legal("api.test.example.com"))
        self.assertFalse(should_check_legal("sub.domain.com")) # 3 parts, but 'domain' > 3 chars

    @patch('dns.resolver.resolve')
    def test_dmarc_logic(self, mock_resolve):
        # Mock DMARC response
        mock_answer = MagicMock()
        mock_rrset = MagicMock()
        # Simulate multiple strings in one TXT record (common in long DMARC records)
        mock_rrset.strings = [b"v=DMARC1; ", b"p=reject;"]
        mock_answer.__iter__.return_value = [mock_rrset]
        
        mock_resolve.return_value = mock_answer

        domain = "example.com"
        result = {}
        
        # Logic to be implemented in scanner.py
        try:
            dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for r in dmarc_answers:
                # The fix: join strings
                txt_val = "".join([s.decode('utf-8') for s in r.strings])
                if "v=DMARC1" in txt_val:
                    result['dmarc'] = {'present': True, 'record': txt_val}
                    break
        except Exception:
            pass
            
        self.assertTrue(result.get('dmarc', {}).get('present'))
        self.assertEqual(result['dmarc']['record'], "v=DMARC1; p=reject;")

if __name__ == '__main__':
    unittest.main()
