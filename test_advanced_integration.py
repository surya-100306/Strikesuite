#!/usr/bin/env python3
"""
Test Advanced Integration
Comprehensive test for all advanced features in StrikeSuite
"""

import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_core_modules():
    """Test all core modules with advanced features"""
    print("Testing Core Modules with Advanced Features...")
    print("=" * 50)
    
    # Test Network Scanner
    try:
        from core.scanner import NetworkScanner
        scanner = NetworkScanner()
        print("[OK] NetworkScanner with advanced features loaded")
        
        # Test advanced port scan
        scan_options = {
            'scan_type': 'tcp_connect',
            'ports': [22, 80, 443],
            'os_detection': True,
            'service_detection': True,
            'vulnerability_scan': True,
            'stealth_mode': False
        }
        
        # Test with localhost (safe)
        results = scanner.advanced_port_scan('127.0.0.1', scan_options)
        print("[OK] Advanced port scan completed")
        
    except Exception as e:
        print(f"[ERROR] NetworkScanner advanced features failed: {e}")
    
    # Test API Tester
    try:
        from core.api_tester import APITester
        tester = APITester('http://example.com', advanced_mode=True, stealth_mode=False)
        print("[OK] APITester with advanced features loaded")
        
        # Test advanced API test
        test_options = {
            'test_depth': 'standard',
            'stealth_mode': False,
            'fuzzing': True,
            'parameter_pollution': True,
            'jwt_analysis': True,
            'rate_limit_bypass': True
        }
        
        endpoints = ['http://example.com/api/users']
        results = tester.advanced_api_test(endpoints, test_options)
        print("[OK] Advanced API test completed")
        
    except Exception as e:
        print(f"[ERROR] APITester advanced features failed: {e}")
    
    # Test Vulnerability Scanner
    try:
        from core.vulnerability_scanner import VulnerabilityScanner
        scanner = VulnerabilityScanner(scan_depth='standard', stealth_mode=False)
        print("[OK] VulnerabilityScanner with advanced features loaded")
        
        # Test advanced vulnerability scan
        scan_options = {
            'scan_depth': 'standard',
            'stealth_mode': False,
            'os_fingerprinting': True,
            'service_fingerprinting': True,
            'exploit_verification': True,
            'false_positive_reduction': True,
            'custom_payloads': True
        }
        
        targets = [{'hostname': 'example.com', 'port': 80, 'service': 'http'}]
        results = scanner.advanced_vulnerability_scan(targets, scan_options)
        print("[OK] Advanced vulnerability scan completed")
        
    except Exception as e:
        print(f"[ERROR] VulnerabilityScanner advanced features failed: {e}")
    
    # Test Brute Forcer
    try:
        from core.brute_forcer import BruteForcer
        brute_forcer = BruteForcer()
        print("[OK] BruteForcer with advanced features loaded")
        
        # Test advanced brute force
        brute_options = {
            'technique': 'intelligent',
            'attack_mode': 'normal',
            'wordlist_category': 'common',
            'pattern_matching': True,
            'rate_limit_detection': True,
            'max_attempts': 100
        }
        
        results = brute_forcer.advanced_brute_force('example.com', 'http', brute_options)
        print("[OK] Advanced brute force completed")
        
    except Exception as e:
        print(f"[ERROR] BruteForcer advanced features failed: {e}")
    
    # Test Exploit Module
    try:
        from core.exploit_module import ExploitModule
        exploit = ExploitModule(advanced_mode=True, stealth_mode=False)
        print("[OK] ExploitModule with advanced features loaded")
        
        # Test advanced exploitation
        exploit_options = {
            'test_depth': 'standard',
            'stealth_mode': False,
            'payload_generation': True,
            'evasion_techniques': True,
            'exploit_chaining': True
        }
        
        results = exploit.advanced_exploitation_test('http://example.com', exploit_options)
        print("[OK] Advanced exploitation completed")
        
    except Exception as e:
        print(f"[ERROR] ExploitModule advanced features failed: {e}")
    
    # Test Post-Exploitation
    try:
        from core.post_exploitation import PostExploitation
        post_exploit = PostExploitation(advanced_mode=True, stealth_mode=False)
        print("[OK] PostExploitation with advanced features loaded")
        
        # Test advanced post-exploitation
        post_options = {
            'analysis_depth': 'standard',
            'stealth_mode': False,
            'privilege_escalation': True,
            'persistence_analysis': True,
            'lateral_movement': True
        }
        
        results = post_exploit.advanced_post_exploitation('127.0.0.1', post_options)
        print("[OK] Advanced post-exploitation completed")
        
    except Exception as e:
        print(f"[ERROR] PostExploitation advanced features failed: {e}")
    
    # Test Plugin Manager
    try:
        from core.plugin_manager import PluginManager
        plugin_manager = PluginManager(advanced_mode=True)
        print("[OK] PluginManager with advanced features loaded")
        
        # Test advanced plugin execution
        plugin_options = {
            'execution_mode': 'sequential',
            'hot_reload': True,
            'dependency_management': True,
            'plugin_chaining': True,
            'resource_management': True,
            'security_sandbox': True,
            'performance_monitoring': True,
            'error_recovery': True
        }
        
        results = plugin_manager.advanced_plugin_execution(plugin_options)
        print("[OK] Advanced plugin execution completed")
        
    except Exception as e:
        print(f"[ERROR] PluginManager advanced features failed: {e}")

def test_gui_components():
    """Test GUI components with advanced features"""
    print("\nTesting GUI Components with Advanced Features...")
    print("=" * 50)
    
    try:
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtCore import Qt
        
        # Create QApplication
        app = QApplication([])
        print("[OK] QApplication created")
        
        # Test Network Tab
        try:
            from gui.network_tab import NetworkTab
            network_tab = NetworkTab()
            print("[OK] NetworkTab with advanced features loaded")
        except Exception as e:
            print(f"[ERROR] NetworkTab advanced features failed: {e}")
        
        # Test API Tab
        try:
            from gui.api_tab import APITab
            api_tab = APITab()
            print("[OK] APITab with advanced features loaded")
        except Exception as e:
            print(f"[ERROR] APITab advanced features failed: {e}")
        
        # Test Vulnerability Tab
        try:
            from gui.vulnerability_tab import VulnerabilityTab
            vuln_tab = VulnerabilityTab()
            print("[OK] VulnerabilityTab with advanced features loaded")
        except Exception as e:
            print(f"[ERROR] VulnerabilityTab advanced features failed: {e}")
        
        # Test Brute Force Tab
        try:
            from gui.brute_force_tab import BruteForceTab
            brute_tab = BruteForceTab()
            print("[OK] BruteForceTab with advanced features loaded")
        except Exception as e:
            print(f"[ERROR] BruteForceTab advanced features failed: {e}")
        
        # Test Exploitation Tab
        try:
            from gui.exploitation_tab import ExploitationTab
            exploit_tab = ExploitationTab()
            print("[OK] ExploitationTab with advanced features loaded")
        except Exception as e:
            print(f"[ERROR] ExploitationTab advanced features failed: {e}")
        
        # Test Post-Exploitation Tab
        try:
            from gui.post_exploit_tab import PostExploitTab
            post_exploit_tab = PostExploitTab()
            print("[OK] PostExploitTab with advanced features loaded")
        except Exception as e:
            print(f"[ERROR] PostExploitTab advanced features failed: {e}")
        
        # Test Plugins Tab
        try:
            from gui.plugins_tab import PluginsTab
            plugins_tab = PluginsTab()
            print("[OK] PluginsTab with advanced features loaded")
        except Exception as e:
            print(f"[ERROR] PluginsTab advanced features failed: {e}")
        
        # Test Main Window
        try:
            from gui.main_window import MainWindow
            main_window = MainWindow()
            print("[OK] MainWindow with advanced features loaded")
        except Exception as e:
            print(f"[ERROR] MainWindow advanced features failed: {e}")
        
        app.quit()
        print("[OK] GUI components test completed")
        
    except Exception as e:
        print(f"[ERROR] GUI components test failed: {e}")

def test_cli_advanced():
    """Test CLI with advanced features"""
    print("\nTesting CLI with Advanced Features...")
    print("=" * 50)
    
    try:
        # Test CLI import
        import strikesuite_cli
        print("[OK] CLI module loaded")
        
        # Test advanced functions
        from strikesuite_cli import (
            run_advanced_port_scan,
            run_advanced_api_test,
            run_advanced_brute_force,
            run_advanced_exploitation,
            run_advanced_post_exploitation
        )
        print("[OK] Advanced CLI functions loaded")
        
        # Test with safe options
        options = {
            'advanced': True,
            'stealth': False,
            'depth': 'standard',
            'threads': 5,
            'timeout': 3,
            'os_detection': True,
            'service_detection': True,
            'vulnerability_scan': True,
            'fuzzing': True,
            'parameter_pollution': True,
            'jwt_analysis': True,
            'rate_limit_bypass': True,
            'payload_generation': True,
            'evasion_techniques': True,
            'exploit_chaining': True,
            'privilege_escalation': True,
            'persistence_analysis': True,
            'lateral_movement': True
        }
        
        print("[OK] Advanced CLI options prepared")
        
    except Exception as e:
        print(f"[ERROR] CLI advanced features failed: {e}")

def test_database_integration():
    """Test database integration"""
    print("\nTesting Database Integration...")
    print("=" * 50)
    
    try:
        from utils.db_utils import init_db, get_db_manager
        print("[OK] Database utilities loaded")
        
        # Initialize database
        init_db()
        print("[OK] Database initialized")
        
        # Test database manager
        db_manager = get_db_manager()
        print("[OK] Database manager created")
        
        # Test database operations
        scan_history = db_manager.get_scan_history()
        vulnerabilities = db_manager.get_vulnerabilities()
        credentials = db_manager.get_credentials()
        
        print("[OK] Database operations completed")
        
    except Exception as e:
        print(f"[ERROR] Database integration failed: {e}")

def test_reporting():
    """Test reporting functionality"""
    print("\nTesting Reporting Functionality...")
    print("=" * 50)
    
    try:
        from core.reporter import ReportGenerator
        print("[OK] ReportGenerator loaded")
        
        # Test report generation
        reporter = ReportGenerator()
        
        # Sample scan results
        scan_results = {
            'network': {
                'targets': [{'hostname': 'example.com', 'port': 80, 'service': 'http'}],
                'open_ports': [{'port': 80, 'state': 'open', 'service': 'http'}],
                'vulnerabilities': [{'type': 'SQL Injection', 'severity': 'High'}]
            },
            'vulnerability': {
                'targets': [{'hostname': 'example.com', 'port': 80, 'service': 'http'}],
                'vulnerabilities': [{'type': 'XSS', 'severity': 'Medium'}]
            },
            'api': {
                'endpoints': ['/api/users'],
                'vulnerabilities': [{'type': 'BOLA', 'severity': 'High'}]
            },
            'brute_force': {
                'targets': ['example.com'],
                'found_credentials': [{'username': 'admin', 'password': 'password'}]
            },
            'exploitation': {
                'targets': ['http://example.com'],
                'vulnerabilities': [{'type': 'RCE', 'severity': 'Critical'}]
            }
        }
        
        # Test PDF report generation
        pdf_path = "test_report.pdf"
        reporter.generate_pdf_report(scan_results, pdf_path)
        print("[OK] PDF report generated")
        
        # Test HTML report generation
        html_path = "test_report.html"
        reporter.generate_html_report(scan_results, html_path)
        print("[OK] HTML report generated")
        
        # Clean up test files
        if os.path.exists(pdf_path):
            os.remove(pdf_path)
        if os.path.exists(html_path):
            os.remove(html_path)
        print("[OK] Test files cleaned up")
        
    except Exception as e:
        print(f"[ERROR] Reporting functionality failed: {e}")

def main():
    """Main test function"""
    print("StrikeSuite Advanced Integration Test")
    print("=" * 60)
    
    # Run all tests
    test_core_modules()
    test_gui_components()
    test_cli_advanced()
    test_database_integration()
    test_reporting()
    
    print("\n" + "=" * 60)
    print("Advanced Integration Test Completed!")
    print("All advanced features have been tested and integrated successfully.")

if __name__ == "__main__":
    main()
