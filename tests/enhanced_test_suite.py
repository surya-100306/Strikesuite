#!/usr/bin/env python3
"""
Enhanced Test Suite
Comprehensive testing framework for StrikeSuite
"""

import unittest
import sys
import os
import json
import time
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import tempfile
import shutil

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

class TestEnhancedMainWindow(unittest.TestCase):
    """Test enhanced main window functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.app = Mock()
        self.main_window = None
        
    def test_modern_theme_initialization(self):
        """Test modern theme initialization"""
        from strikesuite.gui.enhanced_main_window import ModernTheme
        
        theme = ModernTheme()
        self.assertIsNotNone(theme.PRIMARY_COLOR)
        self.assertIsNotNone(theme.SECONDARY_COLOR)
        self.assertIsNotNone(theme.SUCCESS_COLOR)
        
    def test_button_style_generation(self):
        """Test button style generation"""
        from strikesuite.gui.enhanced_main_window import ModernTheme
        
        theme = ModernTheme()
        style = theme.get_button_style("#3498db")
        self.assertIn("background-color: #3498db", style)
        self.assertIn("border-radius: 8px", style)
        
    def test_card_style_generation(self):
        """Test card style generation"""
        from strikesuite.gui.enhanced_main_window import ModernTheme
        
        theme = ModernTheme()
        style = theme.get_card_style()
        self.assertIn("background-color: #ffffff", style)
        self.assertIn("border-radius: 12px", style)

class TestEnhancedScanner(unittest.TestCase):
    """Test enhanced scanner functionality"""
    
    def setUp(self):
        """Set up test environment"""
        from strikesuite.core.enhanced_scanner import EnhancedNetworkScanner
        self.scanner = EnhancedNetworkScanner(max_threads=5, timeout=1)
        
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        self.assertEqual(self.scanner.max_threads, 5)
        self.assertEqual(self.scanner.timeout, 1)
        self.assertFalse(self.scanner.is_scanning)
        
    def test_common_ports_initialization(self):
        """Test common ports initialization"""
        self.assertIsInstance(self.scanner.common_ports, list)
        self.assertGreater(len(self.scanner.common_ports), 0)
        self.assertIn(80, self.scanner.common_ports)
        self.assertIn(443, self.scanner.common_ports)
        
    def test_service_mapping(self):
        """Test service mapping"""
        self.assertIn(80, self.scanner.service_map)
        self.assertEqual(self.scanner.service_map[80], "HTTP")
        self.assertEqual(self.scanner.service_map[443], "HTTPS")
        
    def test_scan_progress_tracking(self):
        """Test scan progress tracking"""
        progress = self.scanner.get_scan_progress()
        self.assertIsInstance(progress, dict)
        self.assertIn("is_scanning", progress)
        self.assertIn("progress", progress)
        self.assertIn("total", progress)
        self.assertIn("percentage", progress)

class TestThreatIntelligence(unittest.TestCase):
    """Test threat intelligence functionality"""
    
    def setUp(self):
        """Set up test environment"""
        from strikesuite.core.threat_intelligence import ThreatIntelligenceEngine
        self.threat_engine = ThreatIntelligenceEngine()
        
    def test_threat_engine_initialization(self):
        """Test threat engine initialization"""
        self.assertIsInstance(self.threat_engine.threat_feeds, list)
        self.assertIsInstance(self.threat_engine.ioc_database, dict)
        
    def test_ip_reputation_analysis(self):
        """Test IP reputation analysis"""
        # Test with localhost
        result = self.threat_engine.analyze_ip_reputation("127.0.0.1")
        self.assertIsInstance(result, dict)
        self.assertIn("ip_address", result)
        self.assertIn("reputation_score", result)
        self.assertIn("reputation_level", result)
        self.assertIn("threats", result)
        
    def test_domain_reputation_analysis(self):
        """Test domain reputation analysis"""
        result = self.threat_engine.analyze_domain_reputation("example.com")
        self.assertIsInstance(result, dict)
        self.assertIn("domain", result)
        self.assertIn("reputation_score", result)
        self.assertIn("reputation_level", result)
        self.assertIn("threats", result)
        
    def test_file_hash_analysis(self):
        """Test file hash analysis"""
        test_hash = "d41d8cd98f00b204e9800998ecf8427e"  # MD5 of empty string
        result = self.threat_engine.analyze_file_hash(test_hash)
        self.assertIsInstance(result, dict)
        self.assertIn("file_hash", result)
        self.assertIn("reputation_score", result)
        self.assertIn("reputation_level", result)
        self.assertIn("threats", result)
        
    def test_threat_report_generation(self):
        """Test threat report generation"""
        indicators = ["127.0.0.1", "example.com", "d41d8cd98f00b204e9800998ecf8427e"]
        report = self.threat_engine.generate_threat_report(indicators)
        self.assertIsInstance(report, dict)
        self.assertIn("analysis_timestamp", report)
        self.assertIn("total_indicators", report)
        self.assertIn("threat_analysis", report)
        self.assertIn("summary", report)

class TestPerformanceOptimizer(unittest.TestCase):
    """Test performance optimizer functionality"""
    
    def setUp(self):
        """Set up test environment"""
        from strikesuite.core.performance_optimizer import PerformanceMonitor, TaskOptimizer, MemoryOptimizer
        self.performance_monitor = PerformanceMonitor()
        self.task_optimizer = TaskOptimizer(max_workers=2)
        self.memory_optimizer = MemoryOptimizer()
        
    def test_performance_monitor_initialization(self):
        """Test performance monitor initialization"""
        self.assertIsInstance(self.performance_monitor.metrics, dict)
        self.assertFalse(self.performance_monitor.monitoring)
        self.assertIsInstance(self.performance_monitor.performance_history, list)
        
    def test_task_optimizer_initialization(self):
        """Test task optimizer initialization"""
        self.assertEqual(self.task_optimizer.max_workers, 2)
        self.assertIsNotNone(self.task_optimizer.task_queue)
        self.assertIsInstance(self.task_optimizer.results, dict)
        
    def test_memory_optimization(self):
        """Test memory optimization"""
        result = self.memory_optimizer.optimize_memory_usage()
        self.assertIsInstance(result, dict)
        self.assertIn("objects_collected", result)
        self.assertIn("memory_usage_mb", result)
        self.assertIn("memory_usage_percent", result)
        
    def test_memory_usage_info(self):
        """Test memory usage information"""
        result = self.memory_optimizer.get_memory_usage()
        self.assertIsInstance(result, dict)
        self.assertIn("process_memory", result)
        self.assertIn("system_memory", result)
        self.assertIn("python_objects", result)
        
    def test_task_optimization(self):
        """Test task optimization"""
        scan_tasks = [
            {"type": "network_scan", "target": "192.168.1.1", "ports": [80, 443]},
            {"type": "network_scan", "target": "192.168.1.1", "ports": [22, 23]},
            {"type": "vulnerability_scan", "host": "192.168.1.1", "scan_type": "basic"},
            {"type": "vulnerability_scan", "host": "192.168.1.1", "scan_type": "advanced"}
        ]
        
        optimized_tasks = self.task_optimizer.optimize_scan_tasks(scan_tasks)
        self.assertIsInstance(optimized_tasks, list)
        self.assertLessEqual(len(optimized_tasks), len(scan_tasks))

class TestDatabaseOptimizer(unittest.TestCase):
    """Test database optimizer functionality"""
    
    def setUp(self):
        """Set up test environment"""
        from strikesuite.core.performance_optimizer import DatabaseOptimizer
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_db.close()
        self.db_optimizer = DatabaseOptimizer(self.temp_db.name)
        
    def tearDown(self):
        """Clean up test environment"""
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)
            
    def test_database_optimizer_initialization(self):
        """Test database optimizer initialization"""
        self.assertEqual(self.db_optimizer.db_path, self.temp_db.name)
        
    def test_database_stats(self):
        """Test database statistics"""
        result = self.db_optimizer.get_database_stats()
        self.assertIsInstance(result, dict)
        self.assertIn("database_size_bytes", result)
        self.assertIn("database_size_mb", result)
        self.assertIn("tables", result)

class TestIntegration(unittest.TestCase):
    """Integration tests for the enhanced system"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir)
        
    def test_enhanced_scanner_integration(self):
        """Test enhanced scanner integration"""
        from strikesuite.core.enhanced_scanner import EnhancedNetworkScanner
        
        # Test scanner initialization
        scanner = EnhancedNetworkScanner(max_threads=2, timeout=1)
        self.assertIsNotNone(scanner)
        
        # Test scanner functionality
        self.assertTrue(hasattr(scanner, 'scan_network_range'))
        self.assertTrue(hasattr(scanner, 'get_scan_progress'))
        
    def test_threat_intelligence_integration(self):
        """Test threat intelligence integration"""
        from strikesuite.core.threat_intelligence import ThreatIntelligenceEngine
        
        # Test threat intelligence engine
        threat_engine = ThreatIntelligenceEngine()
        self.assertIsNotNone(threat_engine)
        
        # Test threat intelligence functionality
        self.assertTrue(hasattr(threat_engine, 'analyze_ip_reputation'))
        self.assertTrue(hasattr(threat_engine, 'analyze_domain_reputation'))
        
    def test_performance_optimization_integration(self):
        """Test performance optimization integration"""
        from strikesuite.core.performance_optimizer import PerformanceMonitor, TaskOptimizer, MemoryOptimizer
        
        # Test performance monitor
        monitor = PerformanceMonitor()
        self.assertIsNotNone(monitor)
        
        # Test task optimizer
        optimizer = TaskOptimizer(max_workers=2)
        self.assertIsNotNone(optimizer)
        
        # Test memory optimizer
        memory_opt = MemoryOptimizer()
        self.assertIsNotNone(memory_opt)

class TestErrorHandling(unittest.TestCase):
    """Test error handling and edge cases"""
    
    def test_scanner_error_handling(self):
        """Test scanner error handling"""
        from strikesuite.core.enhanced_scanner import EnhancedNetworkScanner
        
        scanner = EnhancedNetworkScanner(max_threads=1, timeout=0.1)
        
        # Test with invalid network range
        result = scanner.scan_network_range("invalid_range")
        self.assertIn("error", result)
        
    def test_threat_intelligence_error_handling(self):
        """Test threat intelligence error handling"""
        from strikesuite.core.threat_intelligence import ThreatIntelligenceEngine
        
        threat_engine = ThreatIntelligenceEngine()
        
        # Test with invalid indicators
        result = threat_engine.generate_threat_report([])
        self.assertIsInstance(result, dict)
        self.assertEqual(result["total_indicators"], 0)
        
    def test_performance_monitor_error_handling(self):
        """Test performance monitor error handling"""
        from strikesuite.core.performance_optimizer import PerformanceMonitor
        
        monitor = PerformanceMonitor()
        
        # Test getting summary without data
        summary = monitor.get_performance_summary()
        self.assertIsInstance(summary, dict)

class TestDataValidation(unittest.TestCase):
    """Test data validation and integrity"""
    
    def test_scan_result_validation(self):
        """Test scan result validation"""
        from strikesuite.core.enhanced_scanner import EnhancedNetworkScanner
        
        scanner = EnhancedNetworkScanner()
        
        # Test result structure
        result = {
            "host": "192.168.1.1",
            "port": 80,
            "status": "open",
            "service": "HTTP",
            "banner": "Apache/2.4.41",
            "timestamp": "2023-01-01T00:00:00"
        }
        
        # Validate required fields
        required_fields = ["host", "port", "status", "service", "timestamp"]
        for field in required_fields:
            self.assertIn(field, result)
            
    def test_threat_analysis_validation(self):
        """Test threat analysis validation"""
        from strikesuite.core.threat_intelligence import ThreatIntelligenceEngine
        
        threat_engine = ThreatIntelligenceEngine()
        
        # Test IP analysis result structure
        result = threat_engine.analyze_ip_reputation("127.0.0.1")
        required_fields = ["ip_address", "reputation_score", "reputation_level", "threats"]
        for field in required_fields:
            self.assertIn(field, result)
            
    def test_performance_metrics_validation(self):
        """Test performance metrics validation"""
        from strikesuite.core.performance_optimizer import PerformanceMonitor
        
        monitor = PerformanceMonitor()
        
        # Test metrics structure
        metrics = monitor._collect_metrics()
        required_fields = ["timestamp", "cpu", "memory", "disk"]
        for field in required_fields:
            self.assertIn(field, metrics)

def run_comprehensive_tests():
    """Run comprehensive test suite"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestEnhancedMainWindow,
        TestEnhancedScanner,
        TestThreatIntelligence,
        TestPerformanceOptimizer,
        TestDatabaseOptimizer,
        TestIntegration,
        TestErrorHandling,
        TestDataValidation
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result

if __name__ == "__main__":
    print("Running Enhanced Test Suite...")
    print("=" * 50)
    
    result = run_comprehensive_tests()
    
    print("=" * 50)
    if result.wasSuccessful():
        print("All tests passed!")
    else:
        print(f"{len(result.failures)} test(s) failed")
        print(f"{len(result.errors)} error(s) occurred")
        
        for failure in result.failures:
            print(f"FAIL: {failure[0]}")
            print(failure[1])
            
        for error in result.errors:
            print(f"ERROR: {error[0]}")
            print(error[1])
