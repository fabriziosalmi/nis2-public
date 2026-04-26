import unittest
from nis2scan.compliance import ComplianceEngine, ScanResult, ComplianceFinding

class TestComplianceLogic(unittest.TestCase):
    def test_dmarc_finding_logic(self):
        analyzer = ComplianceEngine(config=None)
        
        # Case 1: DMARC Present
        host_with_dmarc = ScanResult(target="example.com", ip="1.2.3.4", is_alive=True)
        host_with_dmarc.dns_info = {
            'dmarc': {'present': True, 'record': 'v=DMARC1; p=none'}
        }
        
        report = analyzer.evaluate([host_with_dmarc])
        dmarc_findings = [f for f in report.findings if "DMARC" in f.message]
        self.assertEqual(len(dmarc_findings), 0, "Should not find DMARC missing if present")

        # Case 2: DMARC Missing
        host_no_dmarc = ScanResult(target="example.com", ip="1.2.3.4", is_alive=True)
        host_no_dmarc.dns_info = {
            'dmarc': {'present': False}
        }
        
        report = analyzer.evaluate([host_no_dmarc])
        dmarc_findings = [f for f in report.findings if "DMARC" in f.message]
        self.assertEqual(len(dmarc_findings), 1, "Should find DMARC missing")
        self.assertEqual(dmarc_findings[0].message, "DMARC Record Missing")

    def test_spf_finding_logic(self):
        analyzer = ComplianceEngine(config=None)
        
        # Case 1: SPF Present
        host_with_spf = ScanResult(target="example.com", ip="1.2.3.4", is_alive=True)
        host_with_spf.dns_info = {
            'spf': {'present': True, 'record': 'v=spf1 -all'}
        }
        
        report = analyzer.evaluate([host_with_spf])
        spf_findings = [f for f in report.findings if "SPF" in f.message]
        self.assertEqual(len(spf_findings), 0, "Should not find SPF missing if present")

if __name__ == '__main__':
    unittest.main()
