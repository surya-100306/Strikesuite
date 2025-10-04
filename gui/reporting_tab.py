#!/usr/bin/env python3
"""
Reporting Tab
GUI for report generation functionality
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QLineEdit, QPushButton, QTextEdit,
                             QCheckBox, QGroupBox, QTableWidget, QTableWidgetItem,
                             QHeaderView, QComboBox, QFileDialog, QProgressBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import os
import datetime

# Import core modules
import sys
from pathlib import Path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

class ReportingTab(QWidget):
    """Report generation tab widget"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        
        # Report configuration
        config_group = QGroupBox("Report Configuration")
        config_layout = QGridLayout(config_group)
        
        config_layout.addWidget(QLabel("Report Title:"), 0, 0)
        self.title_input = QLineEdit()
        self.title_input.setText("Security Assessment Report")
        config_layout.addWidget(self.title_input, 0, 1)
        
        config_layout.addWidget(QLabel("Client:"), 1, 0)
        self.client_input = QLineEdit()
        self.client_input.setPlaceholderText("Client Name")
        config_layout.addWidget(self.client_input, 1, 1)
        
        config_layout.addWidget(QLabel("Target:"), 2, 0)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Target IP/URL")
        config_layout.addWidget(self.target_input, 2, 1)
        
        config_layout.addWidget(QLabel("Report Type:"), 3, 0)
        self.report_type_combo = QComboBox()
        self.report_type_combo.addItems(["PDF", "HTML", "Both"])
        config_layout.addWidget(self.report_type_combo, 3, 1)
        
        # Save location
        config_layout.addWidget(QLabel("Save Location:"), 4, 0)
        location_layout = QHBoxLayout()
        self.save_location_input = QLineEdit()
        self.save_location_input.setPlaceholderText("Select save location...")
        self.save_location_input.setText("reports/generated/")  # Default location
        location_layout.addWidget(self.save_location_input)
        
        self.browse_location_btn = QPushButton("Browse...")
        self.browse_location_btn.clicked.connect(self.browse_save_location)
        location_layout.addWidget(self.browse_location_btn)
        config_layout.addLayout(location_layout, 4, 1)
        
        layout.addWidget(config_group)
        
        # Report sections
        sections_group = QGroupBox("Report Sections")
        sections_layout = QVBoxLayout(sections_group)
        
        self.executive_summary_check = QCheckBox("Executive Summary")
        self.executive_summary_check.setChecked(True)
        sections_layout.addWidget(self.executive_summary_check)
        
        self.vulnerability_summary_check = QCheckBox("Vulnerability Summary")
        self.vulnerability_summary_check.setChecked(True)
        sections_layout.addWidget(self.vulnerability_summary_check)
        
        self.detailed_findings_check = QCheckBox("Detailed Findings")
        self.detailed_findings_check.setChecked(True)
        sections_layout.addWidget(self.detailed_findings_check)
        
        self.recommendations_check = QCheckBox("Recommendations")
        self.recommendations_check.setChecked(True)
        sections_layout.addWidget(self.recommendations_check)
        
        self.technical_details_check = QCheckBox("Technical Details")
        self.technical_details_check.setChecked(True)
        sections_layout.addWidget(self.technical_details_check)
        
        layout.addWidget(sections_group)
        
        # Data sources
        sources_group = QGroupBox("Data Sources")
        sources_layout = QVBoxLayout(sources_group)
        
        self.scan_results_check = QCheckBox("Include Scan Results")
        self.scan_results_check.setChecked(True)
        sources_layout.addWidget(self.scan_results_check)
        
        self.vulnerability_data_check = QCheckBox("Include Vulnerability Data")
        self.vulnerability_data_check.setChecked(True)
        sources_layout.addWidget(self.vulnerability_data_check)
        
        self.api_test_results_check = QCheckBox("Include API Test Results")
        self.api_test_results_check.setChecked(True)
        sources_layout.addWidget(self.api_test_results_check)
        
        self.exploitation_results_check = QCheckBox("Include Exploitation Results")
        self.exploitation_results_check.setChecked(True)
        sources_layout.addWidget(self.exploitation_results_check)
        
        layout.addWidget(sources_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.generate_btn = QPushButton("Generate Report")
        self.generate_btn.clicked.connect(self.generate_report)
        button_layout.addWidget(self.generate_btn)
        
        self.preview_btn = QPushButton("Preview Report")
        self.preview_btn.clicked.connect(self.preview_report)
        button_layout.addWidget(self.preview_btn)
        
        self.test_btn = QPushButton("Test Table Display")
        self.test_btn.clicked.connect(self.test_table_display)
        button_layout.addWidget(self.test_btn)
        
        self.test_report_btn = QPushButton("Test Report Generation")
        self.test_report_btn.clicked.connect(self.test_report_generation)
        button_layout.addWidget(self.test_report_btn)
        
        self.open_folder_btn = QPushButton("Open Reports Folder")
        self.open_folder_btn.clicked.connect(self.open_reports_folder)
        button_layout.addWidget(self.open_folder_btn)
        
        layout.addLayout(button_layout)
        
        # Progress section
        progress_group = QGroupBox("Report Generation Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready to generate report")
        progress_layout.addWidget(self.status_label)
        
        layout.addWidget(progress_group)
        
        # Results section
        results_group = QGroupBox("Report Generation Results")
        results_layout = QVBoxLayout(results_group)
        
        # Results table with proper size and scrolling
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["Report", "Type", "Status"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setAlternatingRowColors(True)  # Better readability
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)  # Select entire rows
        
        # Set table size for better visibility
        self.results_table.setMinimumHeight(400)  # Much larger table
        self.results_table.setMaximumHeight(600)  # Allow scrolling when needed
        self.results_table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)  # Show scrollbar when needed
        self.results_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)  # Show horizontal scrollbar if needed
        
        # Set row height for better readability
        self.results_table.verticalHeader().setDefaultSectionSize(30)  # Taller rows
        
        results_layout.addWidget(self.results_table)
        
        # Results text with proper scrolling (smaller to give more space to table)
        self.results_text = QTextEdit()
        self.results_text.setMinimumHeight(150)  # Smaller text area
        self.results_text.setMaximumHeight(200)  # Limit text area size
        self.results_text.setPlaceholderText("Report generation results will appear here...")
        self.results_text.setReadOnly(True)  # Make it read-only for better UX
        self.results_text.setLineWrapMode(QTextEdit.WidgetWidth)  # Enable word wrapping
        self.results_text.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)  # Show scrollbar when needed
        results_layout.addWidget(self.results_text)
        
        layout.addWidget(results_group)
        
    def generate_report(self):
        """Generate security report"""
        title = self.title_input.text().strip()
        if not title:
            self.results_text.append("Please enter a report title")
            self.results_text.ensureCursorVisible()  # Auto-scroll to bottom
            return
            
        self.generate_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        
        # Clear previous results
        self.results_table.setRowCount(0)
        self.results_text.clear()
        self.results_text.append(f"Generating report: {title}")
        self.results_text.ensureCursorVisible()  # Auto-scroll to bottom
        
        # Start report generation in background thread
        self.report_thread = ReportThread(self.get_report_options())
        self.report_thread.progress.connect(self.update_progress)
        self.report_thread.result.connect(self.report_finished)
        self.report_thread.start()
        
    def browse_save_location(self):
        """Browse for save location"""
        from PyQt5.QtWidgets import QFileDialog
        
        # Get directory path
        directory = QFileDialog.getExistingDirectory(
            self, 
            "Select Report Save Location",
            self.save_location_input.text() or "reports/generated/"
        )
        
        if directory:
            self.save_location_input.setText(directory)
    
    def get_report_options(self):
        """Get report generation options"""
        return {
            'title': self.title_input.text().strip(),
            'client': self.client_input.text().strip(),
            'target': self.target_input.text().strip(),
            'report_type': self.report_type_combo.currentText(),
            'save_location': self.save_location_input.text().strip(),
            'sections': {
                'executive_summary': self.executive_summary_check.isChecked(),
                'vulnerability_summary': self.vulnerability_summary_check.isChecked(),
                'detailed_findings': self.detailed_findings_check.isChecked(),
                'recommendations': self.recommendations_check.isChecked(),
                'technical_details': self.technical_details_check.isChecked()
            },
            'data_sources': {
                'scan_results': self.scan_results_check.isChecked(),
                'vulnerability_data': self.vulnerability_data_check.isChecked(),
                'api_test_results': self.api_test_results_check.isChecked(),
                'exploitation_results': self.exploitation_results_check.isChecked()
            }
        }
        
    def update_progress(self, value, message):
        """Update progress bar and status"""
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
        
    def report_finished(self, results):
        """Handle report generation completion"""
        self.generate_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        # Check for errors
        if 'error' in results:
            self.status_label.setText(f"Error: {results['error']}")
            self.results_text.append(f"Error: {results['error']}")
            self.results_text.ensureCursorVisible()
            return
        
        # Display results
        reports = results.get('reports', [])
        if not reports:
            self.status_label.setText("No reports generated")
            self.results_text.append("No reports were generated")
            self.results_text.ensureCursorVisible()
            return
        
        self.status_label.setText(f"Generated {len(reports)} report(s)")
        
        # Clear previous results
        self.results_table.setRowCount(0)
        
        # Add each report to the table
        for report in reports:
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            
            # Set table items
            filename = report.get('filename', 'Unknown')
            report_type = report.get('type', 'Unknown')
            status = report.get('status', 'Unknown')
            
            self.results_table.setItem(row, 0, QTableWidgetItem(filename))
            self.results_table.setItem(row, 1, QTableWidgetItem(report_type))
            self.results_table.setItem(row, 2, QTableWidgetItem(status))
            
            # Add to results text
            self.results_text.append(f"{filename} ({report_type}): {status}")
            self.results_text.ensureCursorVisible()  # Auto-scroll to bottom
        
        # Resize table columns to fit content
        self.results_table.resizeColumnsToContents()
    
    def test_table_display(self):
        """Test the table display with sample data"""
        # Clear previous results
        self.results_table.setRowCount(0)
        self.results_text.clear()
        
        # Add sample data (more items to test scrolling)
        sample_reports = [
            {'filename': 'security_report_20251004.pdf', 'type': 'PDF', 'status': 'Generated'},
            {'filename': 'security_report_20251004.html', 'type': 'HTML', 'status': 'Generated'},
            {'filename': 'vulnerability_scan.pdf', 'type': 'PDF', 'status': 'Generated'},
            {'filename': 'network_scan_report.pdf', 'type': 'PDF', 'status': 'Generated'},
            {'filename': 'api_test_results.html', 'type': 'HTML', 'status': 'Generated'},
            {'filename': 'brute_force_results.pdf', 'type': 'PDF', 'status': 'Generated'},
            {'filename': 'exploitation_report.html', 'type': 'HTML', 'status': 'Generated'},
            {'filename': 'post_exploit_results.pdf', 'type': 'PDF', 'status': 'Generated'},
            {'filename': 'plugin_scan_results.html', 'type': 'HTML', 'status': 'Generated'},
            {'filename': 'comprehensive_report.pdf', 'type': 'PDF', 'status': 'Generated'},
            {'filename': 'executive_summary.html', 'type': 'HTML', 'status': 'Generated'},
            {'filename': 'technical_details.pdf', 'type': 'PDF', 'status': 'Generated'}
        ]
        
        for report in sample_reports:
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            
            self.results_table.setItem(row, 0, QTableWidgetItem(report['filename']))
            self.results_table.setItem(row, 1, QTableWidgetItem(report['type']))
            self.results_table.setItem(row, 2, QTableWidgetItem(report['status']))
            
            # Add to results text
            self.results_text.append(f"{report['filename']} ({report['type']}): {report['status']}")
            self.results_text.ensureCursorVisible()
        
        # Resize table columns to fit content
        self.results_table.resizeColumnsToContents()
        self.status_label.setText(f"Test: {len(sample_reports)} sample report(s) displayed")
    
    def test_report_generation(self):
        """Test report generation with sample data"""
        try:
            from core.reporter import ReportGenerator
            import os
            
            # Create comprehensive sample scan results
            sample_scan_results = {
                'scan_time': '2025-10-04 09:00:00',
                'targets': [
                    {
                        'hostname': '192.168.1.100',
                        'port': 80,
                        'service': 'http',
                        'scan_type': 'vulnerability_scan',
                        'vulnerabilities': [
                            {
                                'type': 'SQL Injection',
                                'severity': 'Critical',
                                'description': 'SQL injection vulnerability found in login form',
                                'cve': 'CVE-2023-1234',
                                'remediation': 'Use parameterized queries'
                            },
                            {
                                'type': 'XSS',
                                'severity': 'High',
                                'description': 'Cross-site scripting vulnerability in search form',
                                'cve': 'CVE-2023-5678',
                                'remediation': 'Implement input validation and output encoding'
                            }
                        ]
                    },
                    {
                        'hostname': '192.168.1.101',
                        'port': 22,
                        'service': 'ssh',
                        'scan_type': 'network_scan',
                        'vulnerabilities': [
                            {
                                'type': 'Weak SSH Configuration',
                                'severity': 'Medium',
                                'description': 'SSH server allows weak encryption algorithms',
                                'cve': 'CVE-2023-9999',
                                'remediation': 'Disable weak encryption algorithms'
                            }
                        ]
                    }
                ],
                'network_scans': [
                    {
                        'target': '192.168.1.100',
                        'port': 80,
                        'service': 'http',
                        'status': 'Open',
                        'banner': 'Apache/2.4.41 (Ubuntu)',
                        'open_ports': [80, 443, 22],
                        'findings': []
                    },
                    {
                        'target': '192.168.1.101',
                        'port': 22,
                        'service': 'ssh',
                        'status': 'Open',
                        'banner': 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2',
                        'open_ports': [22, 80],
                        'findings': []
                    }
                ],
                'vulnerability_scans': [
                    {
                        'target': '192.168.1.100',
                        'port': 80,
                        'service': 'http',
                        'vulnerabilities': [
                            {
                                'type': 'SQL Injection',
                                'severity': 'Critical',
                                'description': 'SQL injection vulnerability found in login form',
                                'cve': 'CVE-2023-1234',
                                'remediation': 'Use parameterized queries'
                            }
                        ],
                        'ssl_info': {'version': 'TLS 1.2', 'cipher': 'AES-256-GCM'},
                        'headers': {'Server': 'Apache/2.4.41', 'X-Powered-By': 'PHP/7.4.3'},
                        'findings': []
                    }
                ],
                'api_tests': [
                    {
                        'target': '192.168.1.100',
                        'endpoint': '/api/users',
                        'method': 'GET',
                        'status_code': 200,
                        'vulnerabilities': [
                            {
                                'type': 'Information Disclosure',
                                'severity': 'Medium',
                                'description': 'API endpoint exposes sensitive user information',
                                'cve': 'CVE-2023-8888',
                                'remediation': 'Implement proper access controls'
                            }
                        ],
                        'findings': []
                    }
                ],
                'brute_force_results': [
                    {
                        'target': '192.168.1.101',
                        'port': 22,
                        'service': 'ssh',
                        'attempts': 1000,
                        'successful_credentials': [
                            {'username': 'admin', 'password': 'admin123'},
                            {'username': 'root', 'password': 'password'}
                        ],
                        'findings': []
                    }
                ],
                'exploitation_results': [
                    {
                        'target': '192.168.1.100',
                        'port': 80,
                        'service': 'http',
                        'exploit_used': 'SQL Injection Exploit',
                        'success': True,
                        'payload': "'; DROP TABLE users; --",
                        'findings': []
                    }
                ],
                'summary': {
                    'total_targets': 2,
                    'total_vulnerabilities': 4,
                    'critical_count': 1,
                    'high_count': 1,
                    'medium_count': 2,
                    'low_count': 0,
                    'network_scans': 2,
                    'vulnerability_scans': 1,
                    'api_tests': 1,
                    'brute_force_attempts': 1000,
                    'successful_exploits': 1
                }
            }
            
            # Generate test reports
            generator = ReportGenerator()
            
            # Get save location
            save_location = self.save_location_input.text().strip() or "reports/generated/"
            if not os.path.isabs(save_location):
                reports_dir = os.path.join(os.getcwd(), save_location)
            else:
                reports_dir = save_location
            os.makedirs(reports_dir, exist_ok=True)
            
            # Generate PDF report
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            pdf_filename = f"test_report_{timestamp}.pdf"
            pdf_path = os.path.join(reports_dir, pdf_filename)
            pdf_path = generator.generate_pdf_report(sample_scan_results, pdf_path)
            if pdf_path:
                self.results_text.append(f"PDF report generated: {os.path.basename(pdf_path)}")
                self.results_text.ensureCursorVisible()
            
            # Generate HTML report
            html_filename = f"test_report_{timestamp}.html"
            html_path = os.path.join(reports_dir, html_filename)
            html_path = generator.generate_html_report(sample_scan_results, html_path)
            if html_path:
                self.results_text.append(f"HTML report generated: {os.path.basename(html_path)}")
                self.results_text.ensureCursorVisible()
            
            # Add to table
            if pdf_path:
                row = self.results_table.rowCount()
                self.results_table.insertRow(row)
                self.results_table.setItem(row, 0, QTableWidgetItem(os.path.basename(pdf_path)))
                self.results_table.setItem(row, 1, QTableWidgetItem('PDF'))
                self.results_table.setItem(row, 2, QTableWidgetItem('Generated'))
            
            if html_path:
                row = self.results_table.rowCount()
                self.results_table.insertRow(row)
                self.results_table.setItem(row, 0, QTableWidgetItem(os.path.basename(html_path)))
                self.results_table.setItem(row, 1, QTableWidgetItem('HTML'))
                self.results_table.setItem(row, 2, QTableWidgetItem('Generated'))
            
            self.status_label.setText("Test report generation completed successfully")
            
        except Exception as e:
            self.results_text.append(f"Test report generation failed: {str(e)}")
            self.results_text.ensureCursorVisible()
            self.status_label.setText(f"Test failed: {str(e)}")
            
    def preview_report(self):
        """Preview generated report"""
        self.results_text.append("Report preview not implemented yet")
        self.results_text.ensureCursorVisible()  # Auto-scroll to bottom
        
    def open_reports_folder(self):
        """Open reports folder"""
        save_location = self.save_location_input.text().strip() or "reports/generated/"
        if not os.path.isabs(save_location):
            reports_path = os.path.join(os.getcwd(), save_location)
        else:
            reports_path = save_location
        
        if os.path.exists(reports_path):
            import subprocess
            import platform
            try:
                if platform.system() == "Windows":
                    os.startfile(reports_path)
                elif platform.system() == "Darwin":  # macOS
                    subprocess.run(["open", reports_path])
                else:  # Linux
                    subprocess.run(["xdg-open", reports_path])
            except Exception as e:
                self.results_text.append(f"Could not open folder: {str(e)}")
                self.results_text.ensureCursorVisible()
        else:
            self.results_text.append(f"Reports folder not found: {reports_path}")
            self.results_text.ensureCursorVisible()

class ReportThread(QThread):
    """Thread for generating reports"""
    progress = pyqtSignal(int, str)  # value, message
    result = pyqtSignal(dict)
    
    def __init__(self, options):
        super().__init__()
        self.options = options
        
    def run(self):
        """Generate the report"""
        try:
            import os
            
            # Create reports directory if it doesn't exist
            save_location = self.options.get('save_location', 'reports/generated/')
            if not os.path.isabs(save_location):
                reports_dir = os.path.join(os.getcwd(), save_location)
            else:
                reports_dir = save_location
            os.makedirs(reports_dir, exist_ok=True)
            
            # Generate timestamp for unique filenames
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            
            reports = []
            
            # Generate report based on options
            self.progress.emit(25, "Preparing report data...")
            
            # Generate PDF if requested
            if self.options['report_type'] in ['PDF', 'Both']:
                self.progress.emit(50, "Generating PDF report...")
                try:
                    from core.reporter import ReportGenerator
                    from utils.db_utils import DatabaseUtils
                    
                    # Get scan results from database
                    db_utils = DatabaseUtils()
                    scan_history = db_utils.get_scan_history(limit=50)
                    vulnerabilities = db_utils.get_vulnerabilities()
                    
                    # Prepare scan results for report
                    scan_results = self._prepare_scan_results(scan_history, vulnerabilities)
                    
                    generator = ReportGenerator()
                    pdf_filename = f"security_report_{timestamp}.pdf"
                    pdf_path = os.path.join(reports_dir, pdf_filename)
                    pdf_path = generator.generate_pdf_report(scan_results, pdf_path)
                    reports.append({
                        'filename': os.path.basename(pdf_path),
                        'type': 'PDF',
                        'status': 'Generated',
                        'path': pdf_path
                    })
                except Exception as e:
                    reports.append({
                        'filename': f'security_report_{timestamp}.pdf',
                        'type': 'PDF',
                        'status': f'Error: {str(e)}',
                        'path': ''
                    })
            
            # Generate HTML if requested
            if self.options['report_type'] in ['HTML', 'Both']:
                self.progress.emit(75, "Generating HTML report...")
                try:
                    from core.reporter import ReportGenerator
                    from utils.db_utils import DatabaseUtils
                    
                    # Get scan results from database
                    db_utils = DatabaseUtils()
                    scan_history = db_utils.get_scan_history(limit=50)
                    vulnerabilities = db_utils.get_vulnerabilities()
                    
                    # Prepare scan results for report
                    scan_results = self._prepare_scan_results(scan_history, vulnerabilities)
                    
                    generator = ReportGenerator()
                    html_filename = f"security_report_{timestamp}.html"
                    html_path = os.path.join(reports_dir, html_filename)
                    html_path = generator.generate_html_report(scan_results, html_path)
                    reports.append({
                        'filename': os.path.basename(html_path),
                        'type': 'HTML',
                        'status': 'Generated',
                        'path': html_path
                    })
                except Exception as e:
                    reports.append({
                        'filename': f'security_report_{timestamp}.html',
                        'type': 'HTML',
                        'status': f'Error: {str(e)}',
                        'path': ''
                    })
            
            self.progress.emit(100, "Report generation completed")
            
            # Return results
            results = {'reports': reports}
            self.result.emit(results)
            
        except Exception as e:
            self.result.emit({'error': str(e)})
    
    def _prepare_scan_results(self, scan_history, vulnerabilities):
        """Prepare comprehensive scan results for report generation"""
        # Combine all scan results into a single comprehensive report
        scan_results = {
            'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'targets': [],
            'network_scans': [],
            'vulnerability_scans': [],
            'api_tests': [],
            'brute_force_results': [],
            'exploitation_results': [],
            'summary': {
                'total_targets': 0,
                'total_vulnerabilities': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'network_scans': 0,
                'vulnerability_scans': 0,
                'api_tests': 0,
                'brute_force_attempts': 0,
                'successful_exploits': 0
            }
        }
        
        # Process scan history and categorize by scan type
        for scan in scan_history:
            scan_type = scan.get('scan_type', 'unknown')
            target = scan.get('target', 'Unknown')
            port = scan.get('port', 0)
            service = scan.get('service', 'Unknown')
            results = scan.get('results', {})
            
            # Create target entry
            target_entry = {
                'hostname': target,
                'port': port,
                'service': service,
                'scan_type': scan_type,
                'vulnerabilities': [],
                'findings': []
            }
            
            # Add vulnerabilities for this scan
            scan_id = scan.get('id')
            for vuln in vulnerabilities:
                if vuln.get('scan_id') == scan_id:
                    vuln_entry = {
                        'type': vuln.get('type', 'Unknown'),
                        'severity': vuln.get('severity', 'Unknown'),
                        'description': vuln.get('description', ''),
                        'cve': vuln.get('cve', ''),
                        'remediation': vuln.get('remediation', '')
                    }
                    target_entry['vulnerabilities'].append(vuln_entry)
                    
                    # Update summary counts
                    severity = vuln.get('severity', '').lower()
                    if severity == 'critical':
                        scan_results['summary']['critical_count'] += 1
                    elif severity == 'high':
                        scan_results['summary']['high_count'] += 1
                    elif severity == 'medium':
                        scan_results['summary']['medium_count'] += 1
                    elif severity == 'low':
                        scan_results['summary']['low_count'] += 1
            
            # Categorize results by scan type
            if scan_type == 'network_scan':
                scan_results['network_scans'].append({
                    'target': target,
                    'port': port,
                    'service': service,
                    'status': results.get('status', 'Unknown'),
                    'banner': results.get('banner', ''),
                    'open_ports': results.get('open_ports', []),
                    'findings': target_entry['vulnerabilities']
                })
                scan_results['summary']['network_scans'] += 1
                
            elif scan_type == 'vulnerability_scan':
                scan_results['vulnerability_scans'].append({
                    'target': target,
                    'port': port,
                    'service': service,
                    'vulnerabilities': target_entry['vulnerabilities'],
                    'ssl_info': results.get('ssl_info', {}),
                    'headers': results.get('headers', {}),
                    'findings': target_entry['vulnerabilities']
                })
                scan_results['summary']['vulnerability_scans'] += 1
                
            elif scan_type == 'api_test':
                scan_results['api_tests'].append({
                    'target': target,
                    'endpoint': results.get('endpoint', ''),
                    'method': results.get('method', 'GET'),
                    'status_code': results.get('status_code', 0),
                    'vulnerabilities': target_entry['vulnerabilities'],
                    'findings': target_entry['vulnerabilities']
                })
                scan_results['summary']['api_tests'] += 1
                
            elif scan_type == 'brute_force':
                scan_results['brute_force_results'].append({
                    'target': target,
                    'port': port,
                    'service': service,
                    'attempts': results.get('attempts', 0),
                    'successful_credentials': results.get('successful_credentials', []),
                    'findings': target_entry['vulnerabilities']
                })
                scan_results['summary']['brute_force_attempts'] += results.get('attempts', 0)
                
            elif scan_type == 'exploitation':
                scan_results['exploitation_results'].append({
                    'target': target,
                    'port': port,
                    'service': service,
                    'exploit_used': results.get('exploit_used', ''),
                    'success': results.get('success', False),
                    'payload': results.get('payload', ''),
                    'findings': target_entry['vulnerabilities']
                })
                if results.get('success', False):
                    scan_results['summary']['successful_exploits'] += 1
            
            # Add to targets list
            scan_results['targets'].append(target_entry)
        
        # Update summary totals
        scan_results['summary']['total_targets'] = len(scan_results['targets'])
        scan_results['summary']['total_vulnerabilities'] = scan_results['summary']['critical_count'] + \
                                                         scan_results['summary']['high_count'] + \
                                                         scan_results['summary']['medium_count'] + \
                                                         scan_results['summary']['low_count']
        
        return scan_results
