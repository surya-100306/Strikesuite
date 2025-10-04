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
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp:
            result = self.reporter.generate_pdf_report(self.test_data, tmp.name)
            self.assertTrue(result)
            self.assertTrue(os.path.exists(tmp.name))
            os.unlink(tmp.name)
    
    def test_html_generation(self):
        """Test HTML report generation"""
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as tmp:
            result = self.reporter.generate_html_report(self.test_data, tmp.name)
            self.assertTrue(result)
            self.assertTrue(os.path.exists(tmp.name))
            os.unlink(tmp.name)
    
    def test_report_validation(self):
        """Test report data validation"""
        valid_data = {
            "target": "example.com",
            "vulnerabilities": []
        }
        
        invalid_data = {
            "target": "",
            "vulnerabilities": "not_a_list"
        }
        
        self.assertTrue(self.reporter.validate_report_data(valid_data))
        self.assertFalse(self.reporter.validate_report_data(invalid_data))

if __name__ == '__main__':
    unittest.main()
