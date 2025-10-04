#!/usr/bin/env python3
"""
Unit tests for API tester module
"""

import unittest
from unittest.mock import patch, MagicMock
from core.api_tester import APITester

class TestAPITester(unittest.TestCase):
    """Test cases for API tester"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.api_tester = APITester()
    
    def test_initialization(self):
        """Test API tester initialization"""
        self.assertIsNotNone(self.api_tester)
    
    @patch('requests.get')
    def test_basic_scan(self, mock_get):
        """Test basic API scanning"""
        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": "success"}
        mock_get.return_value = mock_response
        
        # Test basic scan
        result = self.api_tester.scan_endpoint("https://api.example.com/test")
        self.assertIsInstance(result, dict)
    
    def test_validate_url(self):
        """Test URL validation"""
        valid_urls = [
            "https://api.example.com",
            "http://localhost:8080/api",
            "https://subdomain.example.com/v1"
        ]
        
        for url in valid_urls:
            self.assertTrue(self.api_tester.validate_url(url))
    
    def test_invalid_urls(self):
        """Test invalid URL handling"""
        invalid_urls = [
            "not-a-url",
            "ftp://example.com",
            "javascript:alert(1)"
        ]
        
        for url in invalid_urls:
            self.assertFalse(self.api_tester.validate_url(url))

if __name__ == '__main__':
    unittest.main()
