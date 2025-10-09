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
        self.scroll_area = None
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface with modern design"""
        # Create main layout
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(15, 15, 15, 15)
        
        # Add welcome section
        self.create_welcome_section(main_layout)
        
        # Create scroll area for the content
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setStyleSheet("""
            QScrollArea {
                border: none;
                background: transparent;
            }
        """)
        
        # Create main widget
        main_widget = QWidget()
        scroll_area.setWidget(main_widget)
        main_layout.addWidget(scroll_area)
        
        layout = QVBoxLayout(main_widget)
        layout.setSpacing(15)
        
        # Target configuration with enhanced styling
        target_group = QGroupBox("🌐 API Target Configuration")
        target_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12px;
                border: 2px solid #e74c3c;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f8f9fa, stop:1 #e9ecef);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 8px 0 8px;
                color: #2c3e50;
                font-size: 13px;
            }
        """)
        target_layout = QGridLayout(target_group)
        target_layout.setSpacing(10)
        
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
        
        # Results table with expandable rows
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)  # Added Expand column
        self.results_table.setHorizontalHeaderLabels(["Test", "Status", "Severity", "Details", "Expand"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        # Set minimum rows to show 8 results
        self.results_table.setRowCount(8)
        self.results_table.setMinimumHeight(300)  # Increased minimum height
        self.results_table.setMaximumHeight(500)  # Set maximum height
        
        # Enable row expansion
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setSelectionMode(QTableWidget.SingleSelection)
        
        # Connect double-click to expand details
        self.results_table.cellDoubleClicked.connect(self.expand_api_details)
        
        # Initialize empty rows with placeholder text
        for row in range(8):
            for col in range(5):
                item = QTableWidgetItem("")
                if col == 0:  # Test column
                    item.setText("---")
                elif col == 1:  # Status column
                    item.setText("---")
                elif col == 2:  # Severity column
                    item.setText("---")
                elif col == 3:  # Details column
                    item.setText("---")
                elif col == 4:  # Expand column
                    item.setText("---")
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)  # Make read-only
                self.results_table.setItem(row, col, item)
        
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
    
    def create_welcome_section(self, layout):
        """Create welcome section with quick start guide"""
        welcome_widget = QWidget()
        welcome_widget.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #e74c3c, stop:1 #c0392b);
                border-radius: 10px;
                padding: 15px;
            }
            QLabel {
                color: white;
                font-size: 12px;
            }
        """)
        
        welcome_layout = QHBoxLayout(welcome_widget)
        
        # Welcome text
        welcome_text = QLabel("🌐 API Security Tester - Test API endpoints for vulnerabilities")
        welcome_text.setStyleSheet("font-size: 14px; font-weight: bold; color: white;")
        welcome_layout.addWidget(welcome_text)
        
        welcome_layout.addStretch()
        
        # Quick start tips
        tips_text = QLabel("💡 Quick Start: Enter API URL → Configure tests → Start scan")
        tips_text.setStyleSheet("font-size: 11px; color: #ecf0f1;")
        welcome_layout.addWidget(tips_text)
        
        layout.addWidget(welcome_widget)
    
    def expand_api_details(self, row, column):
        """Expand API test details when double-clicked"""
        try:
            from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton, QLabel
            
            # Get row data
            test = self.results_table.item(row, 0).text() if self.results_table.item(row, 0) else "N/A"
            status = self.results_table.item(row, 1).text() if self.results_table.item(row, 1) else "N/A"
            severity = self.results_table.item(row, 2).text() if self.results_table.item(row, 2) else "N/A"
            details = self.results_table.item(row, 3).text() if self.results_table.item(row, 3) else "N/A"
            
            # Create details dialog
            dialog = QDialog(self)
            dialog.setWindowTitle(f"API Test Details - {test}")
            dialog.setModal(True)
            dialog.resize(700, 500)
            
            layout = QVBoxLayout(dialog)
            
            # Title
            title = QLabel(f"🔍 Detailed API Test Information")
            title.setStyleSheet("font-size: 16px; font-weight: bold; color: #2c3e50; margin: 10px;")
            layout.addWidget(title)
            
            # Details text area
            details_text = QTextEdit()
            details_text.setReadOnly(True)
            details_text.setStyleSheet("""
                QTextEdit {
                    background: #f8f9fa;
                    border: 2px solid #e74c3c;
                    border-radius: 5px;
                    padding: 10px;
                    font-family: 'Courier New', monospace;
                    font-size: 12px;
                }
            """)
            
            # Format detailed information
            detailed_info = f"""
🚀 API SECURITY TEST DETAILS
{'='*50}

📊 TEST INFORMATION:
   Test: {test}
   Status: {status}
   Severity: {severity}

🔍 DETAILED RESULTS:
{details}

🛡️ SECURITY ANALYSIS:
   • OWASP API Top 10 Compliance Check
   • Authentication and Authorization Testing
   • Input Validation and Injection Testing
   • Rate Limiting and DoS Protection
   • Data Exposure and Information Leakage

🔧 RECOMMENDATIONS:
   • Implement proper input validation
   • Add rate limiting mechanisms
   • Use secure authentication methods
   • Implement proper error handling
   • Add API versioning and documentation

📈 REMEDIATION STEPS:
   • Review and fix identified vulnerabilities
   • Implement security headers
   • Add monitoring and logging
   • Conduct regular security assessments
   • Update API documentation

🔍 OWASP REFERENCES:
   • A01:2021 - Broken Access Control
   • A02:2021 - Cryptographic Failures
   • A03:2021 - Injection
   • A04:2021 - Insecure Design
   • A05:2021 - Security Misconfiguration
            """
            
            details_text.setPlainText(detailed_info)
            layout.addWidget(details_text)
            
            # Close button
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(dialog.accept)
            close_btn.setStyleSheet("""
                QPushButton {
                    background: #e74c3c;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background: #c0392b;
                }
            """)
            layout.addWidget(close_btn)
            
            dialog.exec_()
            
        except Exception as e:
            print(f"❌ Expand API details failed: {e}")

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
