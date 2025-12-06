import pytest
from unittest.mock import patch, MagicMock
from nis2_checker.compliance_scanner import ComplianceScanner

@pytest.fixture
def scanner():
    return ComplianceScanner({'enabled': True})

def test_security_txt_pass(scanner):
    with patch('requests.get') as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Contact: security@example.com\nExpires: 2025-01-01T00:00:00.000Z\nEncryption: https://example.com/pgp-key.txt"
        mock_get.return_value = mock_response

        result = scanner.scan_security_txt("http://example.com")
        assert result['status'] == 'PASS'
        assert 'RFC 9116 compliant' in result['details']

def test_security_txt_missing_expires(scanner):
    with patch('requests.get') as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Contact: security@example.com\n"
        mock_get.return_value = mock_response

        result = scanner.scan_security_txt("http://example.com")
        assert result['status'] == 'WARN'
        assert 'missing \'Expires\'' in result['details']

def test_security_txt_fail_404(scanner):
    with patch('requests.get') as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = scanner.scan_security_txt("http://example.com")
        assert result['status'] == 'FAIL'
        assert 'not found' in result['details']

def test_italian_compliance_pass(scanner):
    body = """
    <html>
        <footer>
            P.IVA: 12345678901
            <a href="/privacy-policy">Privacy Policy</a>
            <script src="https://cdns.iubenda.com/iubenda.js"></script>
        </footer>
    </html>
    """
    result = scanner.scan_italian_compliance(body)
    assert result['piva']['status'] == 'PASS'
    assert result['privacy_policy']['status'] == 'PASS'
    assert result['cookie_banner']['status'] == 'PASS'
    assert 'iubenda' in result['cookie_banner']['details']

def test_italian_compliance_fail(scanner):
    body = "<html><body>Just a blog</body></html>"
    result = scanner.scan_italian_compliance(body)
    assert result['piva']['status'] == 'WARN' # Not critical for all, but WARN
    assert result['privacy_policy']['status'] == 'FAIL'
    assert result['cookie_banner']['status'] == 'WARN'

def test_waf_cdn_detect(scanner):
    headers_cf = {'Server': 'cloudflare', 'CF-Ray': '12345abcdef'}
    result = scanner.detect_waf_cdn(headers_cf)
    assert result['status'] == 'PASS'
    assert 'Cloudflare' in result['details']

def test_waf_cdn_fail(scanner):
    headers_apache = {'Server': 'Apache/2.4'}
    result = scanner.detect_waf_cdn(headers_apache)
    assert result['status'] == 'WARN'
