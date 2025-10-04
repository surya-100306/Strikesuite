#!/usr/bin/env python3
"""
StrikeSuite Installation Test
Test script to verify installation and dependencies
"""

import sys
import os

def test_imports():
    """Test if all required modules can be imported"""
    print("Testing imports...")
    
    # Test core modules
    try:
        import requests
        print("✓ requests")
    except ImportError as e:
        print(f"✗ requests: {e}")
    
    try:
        import paramiko
        print("✓ paramiko")
    except ImportError as e:
        print(f"✗ paramiko: {e}")
    
    try:
        import bs4
        print("✓ beautifulsoup4")
    except ImportError as e:
        print(f"✗ beautifulsoup4: {e}")
    
    try:
        import urllib3
        print("✓ urllib3")
    except ImportError as e:
        print(f"✗ urllib3: {e}")
    
    try:
        import cryptography
        print("✓ cryptography")
    except ImportError as e:
        print(f"✗ cryptography: {e}")
    
    try:
        import reportlab
        print("✓ reportlab")
    except ImportError as e:
        print(f"✗ reportlab: {e}")
    
    try:
        import nmap
        print("✓ python-nmap")
    except ImportError as e:
        print(f"✗ python-nmap: {e}")
    
    try:
        import shodan
        print("✓ shodan")
    except ImportError as e:
        print(f"✗ shodan: {e}")
    
    try:
        import colorama
        print("✓ colorama")
    except ImportError as e:
        print(f"✗ colorama: {e}")

def test_strikesuite_modules():
    """Test if StrikeSuite modules can be imported"""
    print("\nTesting StrikeSuite modules...")
    
    try:
        from core.scanner import scan_ports
        print("✓ core.scanner")
    except ImportError as e:
        print(f"✗ core.scanner: {e}")
    
    try:
        from core.api_tester import APITester
        print("✓ core.api_tester")
    except ImportError as e:
        print(f"✗ core.api_tester: {e}")
    
    try:
        from core.vulnerability_scanner import VulnerabilityScanner
        print("✓ core.vulnerability_scanner")
    except ImportError as e:
        print(f"✗ core.vulnerability_scanner: {e}")
    
    try:
        from utils.db_utils import init_db
        print("✓ utils.db_utils")
    except ImportError as e:
        print(f"✗ utils.db_utils: {e}")

def test_database():
    """Test database initialization"""
    print("\nTesting database...")
    
    try:
        from utils.db_utils import init_db
        init_db()
        print("✓ Database initialized successfully")
    except Exception as e:
        print(f"✗ Database initialization failed: {e}")

def test_basic_functionality():
    """Test basic functionality"""
    print("\nTesting basic functionality...")
    
    try:
        from core.scanner import scan_ports
        # Test with localhost
        results = scan_ports('127.0.0.1', [22, 80], threads=2)
        print(f"✓ Port scanning works: {len(results)} ports tested")
    except Exception as e:
        print(f"✗ Port scanning failed: {e}")

def main():
    """Main test function"""
    print("StrikeSuite v1.0 - Installation Test")
    print("=" * 40)
    
    # Test Python version
    print(f"Python version: {sys.version}")
    if sys.version_info < (3, 8):
        print("⚠️  Warning: Python 3.8+ recommended")
    
    # Test imports
    test_imports()
    
    # Test StrikeSuite modules
    test_strikesuite_modules()
    
    # Test database
    test_database()
    
    # Test basic functionality
    test_basic_functionality()
    
    print("\n" + "=" * 40)
    print("Installation test completed!")
    print("If you see any ✗ marks, install the missing dependencies:")
    print("pip install <missing-package>")

if __name__ == "__main__":
    main()
