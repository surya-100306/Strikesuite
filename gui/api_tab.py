#!/usr/bin/env python3
"""
API Security Tab
GUI for API security testing functionality
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QLineEdit, QPushButton, QTextEdit,
                             QCheckBox, QGroupBox, QTableWidget, QTableWidgetItem,
                             QHeaderView, QComboBox, QScrollArea)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# Import core modules
import sys
from pathlib import Path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

class APITab(QWidget):
    """API security testing tab widget"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface"""
        # Create scroll area for the entire tab
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        
        # Create main widget
        main_widget = QWidget()
        scroll_area.setWidget(main_widget)
        
        # Create main layout
        main_layout = QVBoxLayout(self)
        main_layout.addWidget(scroll_area)
        
        layout = QVBoxLayout(main_widget)
        
        # Target configuration
        target_group = QGroupBox("API Target Configuration")
        target_layout = QGridLayout(target_group)
        
        target_layout.addWidget(QLabel("API Base URL:"), 0, 0)
        self.api_url_input = QLineEdit()
        self.api_url_input.setPlaceholderText("https://api.example.com")
        target_layout.addWidget(self.api_url_input, 0, 1)
        
        target_layout.addWidget(QLabel("Authentication:"), 1, 0)
        self.auth_combo = QComboBox()
        self.auth_combo.addItems(["None", "Bearer Token", "API Key", "Basic Auth"])
        target_layout.addWidget(self.auth_combo, 1, 1)
        
        target_layout.addWidget(QLabel("Token/Key:"), 2, 0)
        self.auth_token_input = QLineEdit()
        self.auth_token_input.setPlaceholderText("Enter authentication token")
        target_layout.addWidget(self.auth_token_input, 2, 1)
        
        layout.addWidget(target_group)
        
        # Test options
        options_group = QGroupBox("API Security Tests")
        options_layout = QVBoxLayout(options_group)
        
        # OWASP API Top 10 tests
        self.broken_auth_check = QCheckBox("Broken User Authentication")
        self.broken_auth_check.setChecked(True)
        options_layout.addWidget(self.broken_auth_check)
        
        self.broken_object_check = QCheckBox("Broken Object Level Authorization")
        self.broken_object_check.setChecked(True)
        options_layout.addWidget(self.broken_object_check)
        
        self.excessive_data_check = QCheckBox("Excessive Data Exposure")
        self.excessive_data_check.setChecked(True)
        options_layout.addWidget(self.excessive_data_check)
        
        self.rate_limiting_check = QCheckBox("Lack of Resources & Rate Limiting")
        self.rate_limiting_check.setChecked(True)
        options_layout.addWidget(self.rate_limiting_check)
        
        self.mass_assignment_check = QCheckBox("Mass Assignment")
        self.mass_assignment_check.setChecked(True)
        options_layout.addWidget(self.mass_assignment_check)
        
        self.injection_check = QCheckBox("Injection")
        self.injection_check.setChecked(True)
        options_layout.addWidget(self.injection_check)
        
        self.jwt_check = QCheckBox("JWT Security")
        self.jwt_check.setChecked(True)
        options_layout.addWidget(self.jwt_check)
        
        layout.addWidget(options_group)
        
        # Advanced API testing options
        advanced_group = QGroupBox("Advanced API Testing Options")
        advanced_layout = QGridLayout(advanced_group)
        
        # Test depth
        advanced_layout.addWidget(QLabel("Test Depth:"), 0, 0)
        self.test_depth_combo = QComboBox()
        self.test_depth_combo.addItems(["Quick", "Standard", "Deep", "Comprehensive"])
        self.test_depth_combo.setCurrentText("Standard")
        advanced_layout.addWidget(self.test_depth_combo, 0, 1)
        
        # Stealth mode
        self.stealth_mode_check = QCheckBox("Stealth Mode")
        self.stealth_mode_check.setChecked(False)
        advanced_layout.addWidget(self.stealth_mode_check, 1, 0)
        
        # Advanced techniques
        self.fuzzing_check = QCheckBox("Fuzzing")
        self.fuzzing_check.setChecked(True)
        advanced_layout.addWidget(self.fuzzing_check, 1, 1)
        
        self.parameter_pollution_check = QCheckBox("Parameter Pollution")
        self.parameter_pollution_check.setChecked(True)
        advanced_layout.addWidget(self.parameter_pollution_check, 2, 0)
        
        self.http_verb_tampering_check = QCheckBox("HTTP Verb Tampering")
        self.http_verb_tampering_check.setChecked(True)
        advanced_layout.addWidget(self.http_verb_tampering_check, 2, 1)
        
        self.jwt_analysis_check = QCheckBox("JWT Analysis")
        self.jwt_analysis_check.setChecked(True)
        advanced_layout.addWidget(self.jwt_analysis_check, 3, 0)
        
        self.rate_limit_bypass_check = QCheckBox("Rate Limit Bypass")
        self.rate_limit_bypass_check.setChecked(True)
        advanced_layout.addWidget(self.rate_limit_bypass_check, 3, 1)
        
        self.cache_poisoning_check = QCheckBox("Cache Poisoning")
        self.cache_poisoning_check.setChecked(True)
        advanced_layout.addWidget(self.cache_poisoning_check, 4, 0)
        
        self.timing_attacks_check = QCheckBox("Timing Attacks")
        self.timing_attacks_check.setChecked(True)
        advanced_layout.addWidget(self.timing_attacks_check, 4, 1)
        
        self.side_channel_check = QCheckBox("Side Channel Analysis")
        self.side_channel_check.setChecked(True)
        advanced_layout.addWidget(self.side_channel_check, 5, 0)
        
        self.custom_payloads_check = QCheckBox("Custom Payloads")
        self.custom_payloads_check.setChecked(True)
        advanced_layout.addWidget(self.custom_payloads_check, 5, 1)
        
        layout.addWidget(advanced_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.start_test_btn = QPushButton("Start API Test")
        self.start_test_btn.clicked.connect(self.start_api_test)
        button_layout.addWidget(self.start_test_btn)
        
        self.start_advanced_test_btn = QPushButton("Start Advanced API Test")
        self.start_advanced_test_btn.clicked.connect(self.start_advanced_api_test)
        button_layout.addWidget(self.start_advanced_test_btn)
        
        self.stop_test_btn = QPushButton("Stop Test")
        self.stop_test_btn.setEnabled(False)
        self.stop_test_btn.clicked.connect(self.stop_test)
        button_layout.addWidget(self.stop_test_btn)
        
        layout.addLayout(button_layout)
        
        # Results section
        results_group = QGroupBox("Test Results")
        results_layout = QVBoxLayout(results_group)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Test", "Status", "Severity", "Details"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        results_layout.addWidget(self.results_table)
        
        # Results text
        self.results_text = QTextEdit()
        self.results_text.setMaximumHeight(200)
        self.results_text.setPlaceholderText("API test results will appear here...")
        results_layout.addWidget(self.results_text)
        
        layout.addWidget(results_group)
        
    def start_api_test(self):
        """Start API security testing"""
        api_url = self.api_url_input.text().strip()
        if not api_url:
            self.results_text.append("Please enter API URL")
            return
            
        self.start_test_btn.setEnabled(False)
        self.stop_test_btn.setEnabled(True)
        
        # Clear previous results
        self.results_table.setRowCount(0)
        self.results_text.clear()
        
        # Start test in background thread
        self.test_thread = APITestThread(api_url, self.get_test_options())
        self.test_thread.result.connect(self.test_finished)
        self.test_thread.start()
        
    def get_test_options(self):
        """Get selected test options"""
        return {
            'broken_auth': self.broken_auth_check.isChecked(),
            'broken_object': self.broken_object_check.isChecked(),
            'excessive_data': self.excessive_data_check.isChecked(),
            'rate_limiting': self.rate_limiting_check.isChecked(),
            'mass_assignment': self.mass_assignment_check.isChecked(),
            'injection': self.injection_check.isChecked(),
            'jwt': self.jwt_check.isChecked()
        }
        
    def test_finished(self, results):
        """Handle test completion"""
        self.start_test_btn.setEnabled(True)
        self.stop_test_btn.setEnabled(False)
        
        # Display results
        if isinstance(results, dict):
            for test_name, result in results.items():
                row = self.results_table.rowCount()
                self.results_table.insertRow(row)
                
                # Handle different result formats
                if isinstance(result, dict):
                    status = "PASS" if result.get('status') == 'pass' else "FAIL"
                    severity = result.get('severity', 'N/A')
                    details = result.get('details', '')
                else:
                    status = "COMPLETED"
                    severity = "N/A"
                    details = str(result)
                
                self.results_table.setItem(row, 0, QTableWidgetItem(test_name))
                self.results_table.setItem(row, 1, QTableWidgetItem(status))
                self.results_table.setItem(row, 2, QTableWidgetItem(severity))
                self.results_table.setItem(row, 3, QTableWidgetItem(details))
                
                # Add to results text
                self.results_text.append(f"{test_name}: {status} - {details}")
        else:
            # Handle non-dict results
            self.results_text.append(f"API Test Results: {results}")
            
    def stop_test(self):
        """Stop current test"""
        if hasattr(self, 'test_thread') and self.test_thread.isRunning():
            self.test_thread.terminate()
            self.test_thread.wait()
            
        self.start_test_btn.setEnabled(True)
        self.stop_test_btn.setEnabled(False)
        self.results_text.append("Test stopped by user")
    
    def start_advanced_api_test(self):
        """Start advanced API testing"""
        api_url = self.api_url_input.text().strip()
        if not api_url:
            self.results_text.append("Please enter an API URL")
            return
            
        # Disable buttons during test
        self.start_test_btn.setEnabled(False)
        self.start_advanced_test_btn.setEnabled(False)
        self.stop_test_btn.setEnabled(True)
        
        # Clear previous results
        self.results_table.setRowCount(0)
        self.results_text.clear()
        
        # Start advanced test in background thread
        self.test_thread = AdvancedAPITestThread(api_url, self.get_advanced_test_options())
        self.test_thread.result.connect(self.advanced_test_finished)
        self.test_thread.start()
    
    def get_advanced_test_options(self):
        """Get advanced test options"""
        return {
            'test_depth': self.test_depth_combo.currentText().lower(),
            'stealth_mode': self.stealth_mode_check.isChecked(),
            'fuzzing': self.fuzzing_check.isChecked(),
            'parameter_pollution': self.parameter_pollution_check.isChecked(),
            'http_verb_tampering': self.http_verb_tampering_check.isChecked(),
            'jwt_analysis': self.jwt_analysis_check.isChecked(),
            'rate_limit_bypass': self.rate_limit_bypass_check.isChecked(),
            'cache_poisoning': self.cache_poisoning_check.isChecked(),
            'timing_attacks': self.timing_attacks_check.isChecked(),
            'side_channel_analysis': self.side_channel_check.isChecked(),
            'custom_payloads': self.custom_payloads_check.isChecked()
        }
    
    def advanced_test_finished(self, results):
        """Handle advanced test completion"""
        self.start_test_btn.setEnabled(True)
        self.start_advanced_test_btn.setEnabled(True)
        self.stop_test_btn.setEnabled(False)
        
        # Display advanced results
        if isinstance(results, dict):
            if 'error' in results:
                self.results_text.append(f"Advanced API Test Error: {results['error']}")
                return
            
            # Display statistics
            if 'statistics' in results:
                stats = results['statistics']
                self.results_text.append(f"Advanced API Test Statistics:")
                self.results_text.append(f"Total Tests: {stats.get('total_tests', 0)}")
                self.results_text.append(f"Vulnerabilities Found: {stats.get('vulnerabilities_found', 0)}")
                self.results_text.append(f"Critical: {stats.get('critical_count', 0)}")
                self.results_text.append(f"High: {stats.get('high_count', 0)}")
                self.results_text.append(f"Medium: {stats.get('medium_count', 0)}")
                self.results_text.append(f"Low: {stats.get('low_count', 0)}")
                self.results_text.append("")
            
            # Display vulnerabilities
            if 'vulnerabilities' in results:
                for vuln in results['vulnerabilities']:
                    row = self.results_table.rowCount()
                    self.results_table.insertRow(row)
                    
                    self.results_table.setItem(row, 0, QTableWidgetItem(vuln.get('type', 'Unknown')))
                    self.results_table.setItem(row, 1, QTableWidgetItem(vuln.get('severity', 'N/A')))
                    self.results_table.setItem(row, 2, QTableWidgetItem(vuln.get('endpoint', 'N/A')))
                    self.results_table.setItem(row, 3, QTableWidgetItem(vuln.get('description', '')))
                    
                    # Add to results text
                    self.results_text.append(f"{vuln.get('type', 'Unknown')} - {vuln.get('severity', 'N/A')}: {vuln.get('description', '')}")
        else:
            self.results_text.append(f"Advanced API Test Results: {results}")

class APITestThread(QThread):
    """Thread for running API tests"""
    result = pyqtSignal(dict)
    
    def __init__(self, api_url, options):
        super().__init__()
        self.api_url = api_url
        self.options = options
        
    def run(self):
        """Run the API tests"""
        try:
            try:
                from core.api_tester import APITester
            except ImportError:
                self.result.emit({'error': 'APITester module not available'})
                return
                
            tester = APITester(self.api_url)
            
            # Run comprehensive test
            endpoints = [f"{self.api_url}/api/users", f"{self.api_url}/api/admin"]
            results = tester.comprehensive_test(endpoints)
            
            self.result.emit(results)
            
        except Exception as e:
            self.result.emit({'error': str(e)})

class AdvancedAPITestThread(QThread):
    """Thread for running advanced API tests"""
    result = pyqtSignal(dict)
    
    def __init__(self, api_url, options):
        super().__init__()
        self.api_url = api_url
        self.options = options
        
    def run(self):
        """Run the advanced API tests"""
        try:
            try:
                from core.api_tester import APITester
            except ImportError:
                self.result.emit({'error': 'APITester module not available'})
                return
                
            # Create tester with advanced options
            tester = APITester(
                self.api_url, 
                advanced_mode=True, 
                stealth_mode=self.options.get('stealth_mode', False)
            )
            
            # Prepare endpoints for testing
            endpoints = [
                f"{self.api_url}/api/users",
                f"{self.api_url}/api/admin", 
                f"{self.api_url}/api/data",
                f"{self.api_url}/api/auth"
            ]
            
            # Run advanced API test
            results = tester.advanced_api_test(endpoints, self.options)
            
            self.result.emit(results)
            
        except Exception as e:
            self.result.emit({'error': str(e)})
