#!/usr/bin/env python3
"""
Unit tests for report generation module
"""

import unittest
import tempfile
import os
from core.reporter import ReportGenerator

class TestReportGenerator(unittest.TestCase):
    """Test cases for report generation"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.reporter = ReportGenerator()
        self.test_data = {
            "target": "example.com",
            "scan_date": "2024-01-01",
            "vulnerabilities": [
                {
                    "name": "SQL Injection",
                    "severity": "high",
                    "description": "Test vulnerability"
                }
            ]
        }
    
    def test_initialization(self):
        """Test report generator initialization"""
        self.assertIsNotNone(self.reporter)
    
    def test_pdf_generation(self):
        """Test PDF report generation"""
        import tempfile
        import shutil
        
        with tempfile.TemporaryDirectory() as temp_dir:
            pdf_path = os.path.join(temp_dir, 'test_report.pdf')
            result = self.reporter.generate_pdf_report(self.test_data, pdf_path)
            self.assertTrue(result)
            self.assertTrue(os.path.exists(pdf_path))
    
    def test_html_generation(self):
        """Test HTML report generation"""
        import tempfile
        
        with tempfile.TemporaryDirectory() as temp_dir:
            html_path = os.path.join(temp_dir, 'test_report.html')
            result = self.reporter.generate_html_report(self.test_data, html_path)
            self.assertTrue(result)
            self.assertTrue(os.path.exists(html_path))
    
    def test_report_validation(self):
        """Test report data validation"""
        valid_data = {
            "target": "example.com",
            "vulnerabilities": []
        }
        
        # Test that valid data can be processed
        result = self.reporter.generate_html_report(valid_data)
        self.assertIsInstance(result, str)

if __name__ == '__main__':
    unittest.main()
