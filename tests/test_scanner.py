#!/usr/bin/env python3
"""
Test cases for Network Scanner
"""

import unittest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import NetworkScanner

class TestNetworkScanner(unittest.TestCase):
    """Test cases for NetworkScanner"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.scanner = NetworkScanner(max_threads=10, timeout=1.0)
    
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        self.assertEqual(self.scanner.max_threads, 10)
        self.assertEqual(self.scanner.timeout, 1.0)
    
    def test_scan_port_localhost(self):
        """Test scanning localhost ports"""
        # Test common ports on localhost
        ports = [22, 80, 443]
        results = self.scanner.scan_ports('127.0.0.1', ports)
        
        self.assertIsInstance(results, dict)
        self.assertIn('target', results)
        self.assertIn('open_ports', results)
        self.assertIn('scan_time', results)
    
    def test_scan_common_ports(self):
        """Test scanning common ports"""
        results = self.scanner.scan_common_ports('127.0.0.1')
        
        self.assertIsInstance(results, dict)
        self.assertIn('target', results)
        self.assertIn('open_ports', results)
    
    def test_scan_range(self):
        """Test scanning port range"""
        results = self.scanner.scan_range('127.0.0.1', 80, 85)
        
        self.assertIsInstance(results, dict)
        self.assertIn('target', results)
        self.assertIn('open_ports', results)
    
    def test_save_results(self):
        """Test saving scan results"""
        results = {
            'target': '127.0.0.1',
            'open_ports': [{'port': 80, 'service': 'HTTP', 'state': 'open'}],
            'scan_time': 1.0
        }
        
        # This would test saving to file (mock file system)
        # In a real test, you'd use a temporary directory
        pass

if __name__ == '__main__':
    unittest.main()
