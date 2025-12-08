import unittest
from nis2scan.compliance import ComplianceEngine, ComplianceFinding
from nis2scan.scanner import ScanResult
from nis2scan.config import Config, Targets

class TestComplianceEngine(unittest.TestCase):
    def setUp(self):
        self.config = Config(targets=Targets(), features={})
        self.engine = ComplianceEngine(self.config)

    def test_perfect_score(self):
        """Test that a host with no issues gets 100/100."""
        host = ScanResult(target="192.168.1.1", ip="192.168.1.1", is_alive=True)
        # No open ports, no issues
        
        report = self.engine.evaluate([host])
        self.assertEqual(report.total_score, 100)
        self.assertEqual(len(report.findings), 0)

    def test_critical_port_exposure(self):
        """Test that exposing a critical port (e.g. SMB 445) reduces score significantly."""
        host = ScanResult(target="192.168.1.1", ip="192.168.1.1", is_alive=True)
        host.open_ports = [445] # SMB
        
        report = self.engine.evaluate([host])
        
        # Check finding
        self.assertTrue(any(f.severity == "CRITICAL" and "445" in f.message for f in report.findings))
        
        # Check score deduction (Critical = -50)
        self.assertEqual(report.total_score, 50)

    def test_high_risk_exposure(self):
        """Test Telnet exposure."""
        host = ScanResult(target="192.168.1.1", ip="192.168.1.1", is_alive=True)
        host.open_ports = [23] # Telnet
        
        report = self.engine.evaluate([host])
        
        self.assertTrue(any(f.severity == "HIGH" and "Telnet" in f.message for f in report.findings))
        # High = -20
        self.assertEqual(report.total_score, 80)

    def test_tls_issues(self):
        """Test TLS 1.1 detection."""
        host = ScanResult(target="example.com", ip="1.2.3.4", is_alive=True)
        host.open_ports = [443]
        host.tls_info = {
            443: {'version': 'TLSv1.1', 'expired': False}
        }
        
        report = self.engine.evaluate([host])
        
        self.assertTrue(any("Obsolete TLS" in f.message for f in report.findings))
        # High severity for obsolete TLS
        self.assertLess(report.total_score, 100)

    def test_multiple_hosts_average(self):
        """Test that total score is an average of active hosts."""
        host1 = ScanResult(target="good", ip="1.1.1.1", is_alive=True) # 100
        
        host2 = ScanResult(target="bad", ip="2.2.2.2", is_alive=True)
        host2.open_ports = [445] # 50 (Critical)
        
        report = self.engine.evaluate([host1, host2])
        
        # Average: (100 + 50) / 2 = 75
        self.assertEqual(report.total_score, 75)

if __name__ == '__main__':
    unittest.main()
