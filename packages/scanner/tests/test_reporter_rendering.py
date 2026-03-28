import unittest
import os
import shutil
from nis2scan.reporter import Reporter
from nis2scan.compliance import ComplianceReport, ComplianceFinding

class TestReporterRendering(unittest.TestCase):
    def setUp(self):
        self.output_dir = "tests/temp_reports"
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
        os.makedirs(self.output_dir)
        
        self.reporter = Reporter(output_dir=self.output_dir)
        
        # Mock Report
        self.report = ComplianceReport(
            scan_id="test_scan_id",
            total_score=85,
            stats={"analyzed_hosts": 1},
            checked_items=["Test Check"],
            findings=[],
            assets=[],
            compliance_matrix={"Test Check": "Automated"}
        )
        self.report.executive_summary = "<p>Summary</p>"

    def tearDown(self):
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)

    def test_html_rendering_vars(self):
        """Regression test for malformed Jinja2 tags (e.g. { { var } })"""
        filename = "regression_test.html"
        self.reporter.save_html(self.report, filename)
        
        path = os.path.join(self.output_dir, filename)
        with open(path, "r") as f:
            content = f.read()
            
        # Check that JS injection worked (should NOT contain literal curl braces with spaces)
        self.assertNotIn("{ { js_content | safe } }", content, "Found malformed Jinja tag in output!")
        self.assertNotIn("{ { css_content | safe } }", content, "Found malformed Jinja tag in output!")
        
        # Check that variables were actually replaced
        # Since we use real file loader for JS/CSS in Reporter, 
        # checking specifically for the known injected content logic
        # Ideally we'd mock the file read, but integration test is fine here.
        
        # Check standard replacements
        self.assertIn("Network Audit", content)
        self.assertIn("85", content)
        self.assertIn("Test Check", content)  # Checked Item     
        self.assertIn("test_scan_id", content)
        
        # Ensure script tag is present
        self.assertIn("<script>", content)
        
        print("Regression test passed: No malformed tags found.")

if __name__ == '__main__':
    unittest.main()
