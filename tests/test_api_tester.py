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
        self.api_tester = APITester("https://api.example.com")
    
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
        
        # Test comprehensive scan
        endpoints = ["/api/test"]
        result = self.api_tester.comprehensive_test(endpoints)
        self.assertIsInstance(result, dict)
    
    def test_validate_url(self):
        """Test URL validation"""
        # Test that the API tester can handle different endpoints
        endpoints = ["/api/test", "/api/users", "/api/data"]
        
        for endpoint in endpoints:
            # Test that endpoints can be processed
            result = self.api_tester.comprehensive_test([endpoint])
            self.assertIsInstance(result, dict)
    
    def test_invalid_urls(self):
        """Test invalid URL handling"""
        # Test that the API tester handles invalid endpoints gracefully
        invalid_endpoints = ["", "invalid", "//"]
        
        for endpoint in invalid_endpoints:
            # Test that invalid endpoints are handled
            result = self.api_tester.comprehensive_test([endpoint])
            self.assertIsInstance(result, dict)

if __name__ == '__main__':
    unittest.main()
