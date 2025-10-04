#!/usr/bin/env python3
"""
Network Scanning Tab
GUI for network scanning functionality
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QLineEdit, QPushButton, QTextEdit,
                             QSpinBox, QCheckBox, QGroupBox, QProgressBar,
                             QTableWidget, QTableWidgetItem, QHeaderView, QScrollArea,
                             QComboBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont

# Import core modules
import sys
from pathlib import Path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

class NetworkTab(QWidget):
    """Network scanning tab widget"""
    
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
        
        # Target input section
        target_group = QGroupBox("Target Configuration")
        target_layout = QGridLayout(target_group)
        
        target_layout.addWidget(QLabel("Target IP/Hostname:"), 0, 0)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("192.168.1.1 or example.com")
        target_layout.addWidget(self.target_input, 0, 1)
        
        target_layout.addWidget(QLabel("Port Range:"), 1, 0)
        self.port_input = QLineEdit()
        self.port_input.setText("22,80,443,8080")
        self.port_input.setPlaceholderText("22,80,443 or 1-1000")
        target_layout.addWidget(self.port_input, 1, 1)
        
        target_layout.addWidget(QLabel("Threads:"), 2, 0)
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 500)
        self.threads_spin.setValue(50)
        target_layout.addWidget(self.threads_spin, 2, 1)
        
        self.timeout_check = QCheckBox("Use timeout (1s)")
        self.timeout_check.setChecked(True)
        target_layout.addWidget(self.timeout_check, 3, 0, 1, 2)
        
        layout.addWidget(target_group)
        
        # Advanced scan options
        advanced_group = QGroupBox("Advanced Scan Options")
        advanced_layout = QGridLayout(advanced_group)
        
        # Scan type
        advanced_layout.addWidget(QLabel("Scan Type:"), 0, 0)
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["TCP Connect", "SYN Stealth", "UDP", "Stealth (FIN/NULL/XMAS)"])
        advanced_layout.addWidget(self.scan_type_combo, 0, 1)
        
        # Port range selection
        advanced_layout.addWidget(QLabel("Port Range:"), 1, 0)
        self.port_range_combo = QComboBox()
        self.port_range_combo.addItems(["Common (22,80,443,etc)", "Top 1000", "Web Ports", "Database Ports", "Admin Ports", "Custom"])
        advanced_layout.addWidget(self.port_range_combo, 1, 1)
        
        # OS detection
        self.os_detection_check = QCheckBox("OS Detection")
        self.os_detection_check.setChecked(True)
        advanced_layout.addWidget(self.os_detection_check, 2, 0)
        
        # Service detection
        self.service_detection_check = QCheckBox("Service Detection")
        self.service_detection_check.setChecked(True)
        advanced_layout.addWidget(self.service_detection_check, 2, 1)
        
        # Vulnerability scan
        self.vuln_scan_check = QCheckBox("Vulnerability Scan")
        self.vuln_scan_check.setChecked(True)
        advanced_layout.addWidget(self.vuln_scan_check, 3, 0)
        
        # Stealth mode
        self.stealth_mode_check = QCheckBox("Stealth Mode")
        self.stealth_mode_check.setChecked(False)
        advanced_layout.addWidget(self.stealth_mode_check, 3, 1)
        
        layout.addWidget(advanced_group)
        
        # Scan options section
        options_group = QGroupBox("Scan Options")
        options_layout = QHBoxLayout(options_group)
        
        self.quick_scan_btn = QPushButton("Quick Scan")
        self.quick_scan_btn.clicked.connect(self.quick_scan)
        options_layout.addWidget(self.quick_scan_btn)
        
        self.full_scan_btn = QPushButton("Full Scan")
        self.full_scan_btn.clicked.connect(self.full_scan)
        options_layout.addWidget(self.full_scan_btn)
        
        self.advanced_scan_btn = QPushButton("Advanced Scan")
        self.advanced_scan_btn.clicked.connect(self.advanced_scan)
        options_layout.addWidget(self.advanced_scan_btn)
        
        self.custom_scan_btn = QPushButton("Custom Scan")
        self.custom_scan_btn.clicked.connect(self.custom_scan)
        options_layout.addWidget(self.custom_scan_btn)
        
        self.stop_scan_btn = QPushButton("Stop Scan")
        self.stop_scan_btn.setEnabled(False)
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        options_layout.addWidget(self.stop_scan_btn)
        
        layout.addWidget(options_group)
        
        # Progress section
        progress_group = QGroupBox("Scan Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready to scan")
        progress_layout.addWidget(self.status_label)
        
        layout.addWidget(progress_group)
        
        # Results section
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout(results_group)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Port", "State", "Service", "Banner"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        results_layout.addWidget(self.results_table)
        
        # Results text
        self.results_text = QTextEdit()
        self.results_text.setMaximumHeight(150)
        self.results_text.setPlaceholderText("Scan results will appear here...")
        results_layout.addWidget(self.results_text)
        
        layout.addWidget(results_group)
        
    def quick_scan(self):
        """Perform quick scan on common ports"""
        target = self.target_input.text().strip()
        if not target:
            self.status_label.setText("Please enter a target")
            return
            
        self.start_scan(target, [22, 80, 443, 8080, 3389])
        
    def full_scan(self):
        """Perform full scan on port range 1-1000"""
        target = self.target_input.text().strip()
        if not target:
            self.status_label.setText("Please enter a target")
            return
            
        ports = list(range(1, 1001))
        self.start_scan(target, ports)
        
    def advanced_scan(self):
        """Perform advanced scan with all features"""
        target = self.target_input.text().strip()
        if not target:
            self.status_label.setText("Please enter a target")
            return
            
        # Get advanced scan options
        scan_options = self.get_advanced_scan_options()
        self.start_advanced_scan(target, scan_options)
        
    def custom_scan(self):
        """Perform custom scan based on user input"""
        target = self.target_input.text().strip()
        if not target:
            self.status_label.setText("Please enter a target")
            return
            
        port_text = self.port_input.text().strip()
        if not port_text:
            self.status_label.setText("Please enter ports to scan")
            return
            
        # Parse ports
        ports = self.parse_ports(port_text)
        if not ports:
            self.status_label.setText("Invalid port format")
            return
            
        self.start_scan(target, ports)
        
    def parse_ports(self, port_text):
        """Parse port string into list of integers"""
        ports = []
        try:
            for part in port_text.split(','):
                part = part.strip()
                if '-' in part:
                    # Range
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                else:
                    # Single port
                    ports.append(int(part))
        except ValueError:
            return []
        return ports
        
    def get_advanced_scan_options(self):
        """Get advanced scan options from GUI"""
        scan_type_map = {
            "TCP Connect": "tcp",
            "SYN Stealth": "syn", 
            "UDP": "udp",
            "Stealth (FIN/NULL/XMAS)": "stealth"
        }
        
        port_range_map = {
            "Common (22,80,443,etc)": "common",
            "Top 1000": "top1000",
            "Web Ports": "web",
            "Database Ports": "database", 
            "Admin Ports": "admin",
            "Custom": "custom"
        }
        
        return {
            'scan_type': scan_type_map.get(self.scan_type_combo.currentText(), 'tcp'),
            'port_range': port_range_map.get(self.port_range_combo.currentText(), 'common'),
            'os_detection': self.os_detection_check.isChecked(),
            'service_detection': self.service_detection_check.isChecked(),
            'vulnerability_scan': self.vuln_scan_check.isChecked(),
            'stealth_mode': self.stealth_mode_check.isChecked(),
            'max_threads': self.threads_spin.value(),
            'timeout': 1.0 if self.timeout_check.isChecked() else 3.0
        }
        
    def start_advanced_scan(self, target, scan_options):
        """Start advanced network scan"""
        self.status_label.setText(f"Starting advanced scan of {target}...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.progress_bar.setValue(0)
        
        # Disable scan buttons
        self.quick_scan_btn.setEnabled(False)
        self.full_scan_btn.setEnabled(False)
        self.advanced_scan_btn.setEnabled(False)
        self.custom_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        
        # Clear previous results
        self.results_table.setRowCount(0)
        self.results_text.clear()
        
        # Start advanced scan in background thread
        self.scan_thread = AdvancedScanThread(target, scan_options)
        self.scan_thread.progress.connect(self.update_advanced_progress)
        self.scan_thread.result.connect(self.advanced_scan_finished)
        self.scan_thread.start()
        
    def start_scan(self, target, ports):
        """Start network scan"""
        self.status_label.setText(f"Scanning {target}...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, len(ports))
        self.progress_bar.setValue(0)
        
        # Disable scan buttons
        self.quick_scan_btn.setEnabled(False)
        self.full_scan_btn.setEnabled(False)
        self.custom_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        
        # Clear previous results
        self.results_table.setRowCount(0)
        self.results_text.clear()
        
        # Start scan in background thread
        self.scan_thread = ScanThread(target, ports, self.threads_spin.value())
        self.scan_thread.progress.connect(self.update_progress)
        self.scan_thread.result.connect(self.scan_finished)
        self.scan_thread.start()
        
    def update_progress(self, port, is_open, service_info):
        """Update scan progress"""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        self.results_table.setItem(row, 0, QTableWidgetItem(str(port)))
        self.results_table.setItem(row, 1, QTableWidgetItem("OPEN" if is_open else "CLOSED"))
        self.results_table.setItem(row, 2, QTableWidgetItem(service_info if is_open else ""))
        self.results_table.setItem(row, 3, QTableWidgetItem(""))
        
        # Update progress bar
        self.progress_bar.setValue(self.progress_bar.value() + 1)
        
        # Update results text
        if is_open:
            self.results_text.append(f"Port {port}: OPEN - {service_info}")
            
    def update_advanced_progress(self, message):
        """Update progress for advanced scan"""
        self.status_label.setText(message)
        
    def advanced_scan_finished(self, results):
        """Handle advanced scan completion"""
        if 'error' in results:
            self.status_label.setText(f"Scan failed: {results['error']}")
            self.results_text.append(f"Error: {results['error']}")
        else:
            open_ports = len(results.get('open_ports', []))
            vulnerabilities = len(results.get('vulnerabilities', []))
            self.status_label.setText(f"Advanced scan completed - {open_ports} open ports, {vulnerabilities} vulnerabilities found")
            
            # Display results in table
            for port_info in results.get('open_ports', []):
                row = self.results_table.rowCount()
                self.results_table.insertRow(row)
                
                self.results_table.setItem(row, 0, QTableWidgetItem(str(port_info.get('port', ''))))
                self.results_table.setItem(row, 1, QTableWidgetItem("OPEN"))
                self.results_table.setItem(row, 2, QTableWidgetItem(port_info.get('service', '')))
                self.results_table.setItem(row, 3, QTableWidgetItem(port_info.get('banner', '')))
                
                # Add to results text
                self.results_text.append(f"Port {port_info.get('port', '')}: {port_info.get('service', '')} - {port_info.get('banner', '')}")
            
            # Display vulnerabilities
            for vuln in results.get('vulnerabilities', []):
                self.results_text.append(f"VULNERABILITY: {vuln.get('type', '')} - {vuln.get('description', '')}")
            
            # Display OS fingerprint
            if results.get('os_fingerprint'):
                os_info = results['os_fingerprint']
                self.results_text.append(f"OS: {os_info.get('os', 'Unknown')} - {os_info.get('confidence', 0)}% confidence")
        
        self.progress_bar.setVisible(False)
        
        # Re-enable scan buttons
        self.quick_scan_btn.setEnabled(True)
        self.full_scan_btn.setEnabled(True)
        self.advanced_scan_btn.setEnabled(True)
        self.custom_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        
    def scan_finished(self, results):
        """Handle scan completion"""
        self.status_label.setText(f"Scan completed - {len([r for r in results if r[1]])} open ports found")
        self.progress_bar.setVisible(False)
        
        # Re-enable scan buttons
        self.quick_scan_btn.setEnabled(True)
        self.full_scan_btn.setEnabled(True)
        self.advanced_scan_btn.setEnabled(True)
        self.custom_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        
    def stop_scan(self):
        """Stop current scan"""
        if hasattr(self, 'scan_thread') and self.scan_thread.isRunning():
            self.scan_thread.terminate()
            self.scan_thread.wait()
            
        self.status_label.setText("Scan stopped")
        self.progress_bar.setVisible(False)
        
        # Re-enable scan buttons
        self.quick_scan_btn.setEnabled(True)
        self.full_scan_btn.setEnabled(True)
        self.custom_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)

class ScanThread(QThread):
    """Thread for running network scans"""
    progress = pyqtSignal(int, bool, str)  # port, is_open, service_info
    result = pyqtSignal(list)  # list of (port, is_open, service_info) tuples
    
    def __init__(self, target, ports, threads):
        super().__init__()
        self.target = target
        self.ports = ports
        self.threads = threads
        
    def run(self):
        """Run the scan"""
        try:
            from core.scanner import NetworkScanner
            scanner = NetworkScanner(max_threads=self.threads)
            results = scanner.scan_ports(self.target, self.ports)
            
            # Convert results to list format
            result_list = []
            for port_info in results.get('open_ports', []):
                result_list.append((port_info['port'], True, port_info['service']))
                self.progress.emit(port_info['port'], True, port_info['service'])
                
            # Add closed ports
            for port in self.ports:
                if not any(r[0] == port for r in result_list):
                    result_list.append((port, False, ""))
                    self.progress.emit(port, False, "")
                    
            self.result.emit(result_list)
            
        except Exception as e:
            print(f"Scan error: {e}")
            self.result.emit([])

class AdvancedScanThread(QThread):
    """Thread for running advanced network scans"""
    progress = pyqtSignal(str)  # progress message
    result = pyqtSignal(dict)  # scan results
    
    def __init__(self, target, scan_options):
        super().__init__()
        self.target = target
        self.scan_options = scan_options
        
    def run(self):
        """Run the advanced scan"""
        try:
            from core.scanner import NetworkScanner
            scanner = NetworkScanner(
                max_threads=self.scan_options.get('max_threads', 100),
                timeout=self.scan_options.get('timeout', 1.0),
                scan_type=self.scan_options.get('scan_type', 'tcp')
            )
            
            self.progress.emit("Starting advanced port scan...")
            results = scanner.advanced_port_scan(self.target, self.scan_options)
            
            self.result.emit(results)
            
        except Exception as e:
            self.result.emit({'error': str(e)})
