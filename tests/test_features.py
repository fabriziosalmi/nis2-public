import unittest
from nis2scan.legal import LegalChecker
from nis2scan.secrets import SecretsDetector
from nis2scan.resilience import ResilienceChecker

class TestFeatures(unittest.TestCase):
    
    # --- Legal Checker Tests ---
    def test_legal_piva_detection(self):
        checker = LegalChecker()
        
        # Positive case
        html_with_piva = "<html><footer>P.IVA 12345678901</footer></html>"
        result = checker.analyze_page("http://example.com", html_with_piva)
        self.assertTrue(result['italian_compliance']['piva_found'])
        
        # Negative case
        html_clean = "<html><body>Hello World</body></html>"
        result = checker.analyze_page("http://example.com", html_clean)
        self.assertFalse(result['italian_compliance']['piva_found'])

    def test_legal_privacy_policy(self):
        checker = LegalChecker()
        html = "<a href='/privacy-policy'>Privacy Policy</a>"
        result = checker.analyze_page("http://example.com", html)
        self.assertTrue(result['italian_compliance']['privacy_policy_found'])

    # --- Secrets Detector Tests ---
    def test_secrets_aws_key(self):
        detector = SecretsDetector()
        # Fake AWS Key
        content = "var key = 'AKIAIOSFODNN7EXAMPLE';"
        findings = detector.scan_content(content, "http://example.com")
        
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0]['type'], 'aws_access_key')

    def test_secrets_private_key(self):
        detector = SecretsDetector()
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        findings = detector.scan_content(content, "http://example.com")
        
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0]['type'], 'private_key')

    # --- Resilience (WAF) Tests ---
    def test_waf_detection_headers(self):
        checker = ResilienceChecker()
        headers = {
            'Server': 'cloudflare',
            'CF-RAY': '123456789'
        }
        result = checker.detect_waf_cdn(headers, "")
        self.assertTrue(result['protected'])
        self.assertIn('cloudflare', result['providers'])

    def test_waf_detection_cookies(self):
        checker = ResilienceChecker()
        headers = {}
        cookies = "__cfduid=d41d8cd98f00b204e9800998ecf8427e"
        result = checker.detect_waf_cdn(headers, cookies)
        self.assertTrue(result['protected'])
        self.assertIn('cloudflare', result['providers'])

if __name__ == '__main__':
    unittest.main()
