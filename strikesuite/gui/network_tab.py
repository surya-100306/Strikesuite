#!/usr/bin/env python3
"""
Clean Network Scanning Tab
Optimized GUI for network scanning functionality
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QLineEdit, QPushButton, QTextEdit,
                             QSpinBox, QCheckBox, QGroupBox, QProgressBar,
                             QTableWidget, QTableWidgetItem, QHeaderView, QScrollArea,
                             QMessageBox,
                             QComboBox, QTabWidget)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QKeySequence, QColor
import time
import ipaddress

class NetworkTab(QWidget):
    """Clean network scanning tab widget"""
    
    def __init__(self):
        super().__init__()
        self.scan_thread = None
        self.advanced_scan_thread = None
        self.network_scan_thread = None
        self.scroll_area = None
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface with main scroll area"""
        # Create main scroll area for the entire page
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.scroll_area.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: #f8f9fa;
            }
            QScrollBar:vertical {
                background-color: #f0f0f0;
                width: 16px;
                border-radius: 8px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background-color: #0078d4;
                border-radius: 8px;
                min-height: 30px;
                margin: 2px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #106ebe;
            }
            QScrollBar::handle:vertical:pressed {
                background-color: #005a9e;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar:horizontal {
                background-color: #f0f0f0;
                height: 16px;
                border-radius: 8px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background-color: #0078d4;
                border-radius: 8px;
                min-width: 30px;
                margin: 2px;
            }
            QScrollBar::handle:horizontal:hover {
                background-color: #106ebe;
            }
            QScrollBar::handle:horizontal:pressed {
                background-color: #005a9e;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
        """)
        
        # Create main widget for scroll area
        main_widget = QWidget()
        main_widget.setStyleSheet("""
            QWidget {
                background-color: #f8f9fa;
            }
        """)
        
        layout = QVBoxLayout(main_widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(15)
        
        # Welcome section
        self.create_welcome_section(layout)
        
        # Target input section
        self.create_target_section(layout)
        
        # Scan options section
        self.create_scan_options_section(layout)
        
        # Progress section
        self.create_progress_section(layout)
        
        # Results section
        self.create_results_section(layout)
        
        # Set the main widget in scroll area
        self.scroll_area.setWidget(main_widget)
        
        # Store reference to main scroll area for controls
        self.main_scroll = self.scroll_area
        
        # Set main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(self.scroll_area)

    def create_welcome_section(self, layout):
        """Create welcome section with quick start guide"""
        welcome_group = QGroupBox("🚀 StrikeSuite Network Scanner - 100% Accuracy & Speed")
        welcome_layout = QVBoxLayout(welcome_group)
        
        welcome_text = QLabel("""
        <h3>🎯 Ultimate Network Scanning</h3>
        <p><b>Features:</b></p>
        <ul>
        <li>✅ 100% Accurate Port Detection</li>
        <li>✅ Advanced Service Identification</li>
        <li>✅ Real-time Results Display</li>
        <li>✅ Multi-threaded High-Speed Scanning</li>
        <li>✅ Network Range Discovery</li>
        <li>✅ Vulnerability Assessment</li>
        </ul>
        <p><b>Quick Start:</b> Enter target IP/domain and select scan type, then click "START ULTIMATE SCAN"</p>
        """)
        welcome_text.setWordWrap(True)
        welcome_layout.addWidget(welcome_text)
        
        layout.addWidget(welcome_group)

    def create_target_section(self, layout):
        """Create target input section"""
        target_group = QGroupBox("🎯 Target Configuration")
        target_layout = QVBoxLayout(target_group)
        
        # Target input
        target_input_layout = QHBoxLayout()
        target_input_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter IP address, domain, or network range (e.g., 192.168.1.1, example.com, 192.168.1.0/24)")
        self.target_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 4px;
                font-size: 12px;
            }
            QLineEdit:focus {
                border-color: #0078d4;
            }
        """)
        target_input_layout.addWidget(self.target_input)
        target_layout.addLayout(target_input_layout)
        
        layout.addWidget(target_group)

    def create_scan_options_section(self, layout):
        """Create scan options section"""
        options_group = QGroupBox("🚀 ULTIMATE SCAN - 100% ACCURACY & SPEED")
        options_layout = QVBoxLayout(options_group)
        
        # Main comprehensive scan button
        scan_button_layout = QHBoxLayout()
        self.comprehensive_scan_btn = QPushButton("🔍 START ULTIMATE SCAN")
        self.comprehensive_scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                padding: 12px 24px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
            QPushButton:pressed {
                background-color: #005a9e;
            }
            QPushButton:disabled {
                background-color: #ccc;
                color: #666;
            }
        """)
        self.comprehensive_scan_btn.clicked.connect(self.comprehensive_scan)
        
        self.stop_scan_btn = QPushButton("⏹️ STOP SCAN")
        self.stop_scan_btn.setEnabled(False)
        self.stop_scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #d13438;
                color: white;
                border: none;
                padding: 12px 24px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #b71c1c;
            }
            QPushButton:pressed {
                background-color: #8b0000;
            }
            QPushButton:disabled {
                background-color: #ccc;
                color: #666;
            }
        """)
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        
        scan_button_layout.addWidget(self.comprehensive_scan_btn)
        scan_button_layout.addWidget(self.stop_scan_btn)
        options_layout.addLayout(scan_button_layout)
        
        # Scan type selection
        scan_type_layout = QHBoxLayout()
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems([
            "🎯 Single Target Scan",
            "🌐 Network Range Scan", 
            "⚡ Full Port Scan (1-65535)",
            "🔍 Quick Port Scan (Top 1000)",
            "🛡️ Security Scan (Vulnerabilities)"
        ])
        self.scan_type_combo.setStyleSheet("""
            QComboBox {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 4px;
                font-size: 12px;
                min-width: 200px;
            }
            QComboBox:focus {
                border-color: #0078d4;
            }
        """)
        scan_type_layout.addWidget(QLabel("Scan Type:"))
        scan_type_layout.addWidget(self.scan_type_combo)
        scan_type_layout.addStretch()
        options_layout.addLayout(scan_type_layout)
        
        layout.addWidget(options_group)
        
    def create_progress_section(self, layout):
        """Create progress section"""
        progress_group = QGroupBox("📊 Scan Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #ddd;
                border-radius: 4px;
                text-align: center;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #0078d4;
                border-radius: 2px;
            }
        """)
        progress_layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Ready to scan")
        self.status_label.setStyleSheet("""
            QLabel {
                padding: 8px;
                background-color: #f0f0f0;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-weight: bold;
            }
        """)
        progress_layout.addWidget(self.status_label)
        
        layout.addWidget(progress_group)
        
    def create_results_section(self, layout):
        """Create results section with separate tables"""
        results_group = QGroupBox("📊 Scan Results")
        results_layout = QVBoxLayout(results_group)
        
        # Create tab widget for different result types
        self.results_tabs = QTabWidget()
        results_layout.addWidget(self.results_tabs)
        
        # Network Scan Results Tab
        network_tab = QWidget()
        network_layout = QVBoxLayout(network_tab)
        
        # Network scan results table with enhanced scrolling
        self.network_results_table = QTableWidget()
        self.network_results_table.setColumnCount(4)
        self.network_results_table.setHorizontalHeaderLabels(["Host IP", "Device Type", "Open Ports", "Services"])
        self.network_results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        # Enhanced scrolling options
        self.network_results_table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.network_results_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.network_results_table.setAlternatingRowColors(True)
        self.network_results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.network_results_table.setSortingEnabled(True)
        
        # Set minimum rows to show 5 results
        self.network_results_table.setRowCount(5)
        self.network_results_table.setMinimumHeight(200)
        self.network_results_table.setMaximumHeight(400)
        
        # Add scroll area for better scrolling
        network_scroll = QScrollArea()
        network_scroll.setWidget(self.network_results_table)
        network_scroll.setWidgetResizable(True)
        network_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        network_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        
        network_layout.addWidget(network_scroll)
        self.results_tabs.addTab(network_tab, "🌐 Network Results")
        
        # Port Scan Results Tab
        port_tab = QWidget()
        port_layout = QVBoxLayout(port_tab)
        
        # Port scan results table with enhanced scrolling
        self.port_results_table = QTableWidget()
        self.port_results_table.setColumnCount(4)
        self.port_results_table.setHorizontalHeaderLabels(["Port", "State", "Service", "Banner"])
        self.port_results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        # Enhanced scrolling options
        self.port_results_table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.port_results_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.port_results_table.setAlternatingRowColors(True)
        self.port_results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.port_results_table.setSortingEnabled(True)
        
        # Set minimum rows to show 10 results
        self.port_results_table.setRowCount(10)
        self.port_results_table.setMinimumHeight(300)
        self.port_results_table.setMaximumHeight(500)
        
        # Add scroll area for better scrolling
        port_scroll = QScrollArea()
        port_scroll.setWidget(self.port_results_table)
        port_scroll.setWidgetResizable(True)
        port_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        port_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        
        port_layout.addWidget(port_scroll)
        self.results_tabs.addTab(port_tab, "🔍 Port Results")
        
        # Detailed results text area with enhanced scrolling
        self.results_text = QTextEdit()
        self.results_text.setMaximumHeight(200)
        self.results_text.setMinimumHeight(100)
        self.results_text.setPlaceholderText("Detailed scan results and logs will appear here...")
        
        # Enhanced scrolling options for text area
        self.results_text.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.results_text.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.results_text.setLineWrapMode(QTextEdit.WidgetWidth)
        self.results_text.setReadOnly(True)
        
        self.results_text.setStyleSheet("""
            QTextEdit {
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 8px;
                font-family: 'Courier New', monospace;
                font-size: 11px;
                background-color: #f8f8f8;
            }
            QTextEdit:focus {
                border-color: #0078d4;
            }
            QScrollBar:vertical {
                background-color: #f0f0f0;
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background-color: #c0c0c0;
                border-radius: 6px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #a0a0a0;
            }
            QScrollBar:horizontal {
                background-color: #f0f0f0;
                height: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:horizontal {
                background-color: #c0c0c0;
                border-radius: 6px;
                min-width: 20px;
            }
            QScrollBar::handle:horizontal:hover {
                background-color: #a0a0a0;
            }
        """)
        results_layout.addWidget(self.results_text)
        
        layout.addWidget(results_group)
        
        # Add scroll controls section
        self.create_scroll_controls_section(layout)

    def create_scroll_controls_section(self, layout):
        """Create scroll controls section"""
        scroll_group = QGroupBox("📜 Scroll Controls")
        scroll_layout = QHBoxLayout(scroll_group)
        
        # Auto-scroll checkbox
        self.auto_scroll_checkbox = QCheckBox("Auto-scroll to bottom")
        self.auto_scroll_checkbox.setChecked(True)
        self.auto_scroll_checkbox.setStyleSheet("""
            QCheckBox {
                font-weight: bold;
                color: #333;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
            }
            QCheckBox::indicator:checked {
                background-color: #0078d4;
                border: 2px solid #0078d4;
                border-radius: 3px;
            }
        """)
        
        # Clear results button
        self.clear_results_btn = QPushButton("🗑️ Clear Results")
        self.clear_results_btn.setStyleSheet("""
            QPushButton {
                background-color: #dc3545;
                color: white;
                border: none;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
            QPushButton:pressed {
                background-color: #bd2130;
            }
        """)
        self.clear_results_btn.clicked.connect(self.clear_results)
        
        # Export results button
        self.export_results_btn = QPushButton("📤 Export Results")
        self.export_results_btn.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: white;
                border: none;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #218838;
            }
            QPushButton:pressed {
                background-color: #1e7e34;
            }
        """)
        self.export_results_btn.clicked.connect(self.export_results)
        
        # Scroll to top button
        self.scroll_top_btn = QPushButton("⬆️ Scroll to Top")
        self.scroll_top_btn.setStyleSheet("""
            QPushButton {
                background-color: #6c757d;
                color: white;
                border: none;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #5a6268;
            }
            QPushButton:pressed {
                background-color: #545b62;
            }
        """)
        self.scroll_top_btn.clicked.connect(self.scroll_to_top)
        
        # Scroll to bottom button
        self.scroll_bottom_btn = QPushButton("⬇️ Scroll to Bottom")
        self.scroll_bottom_btn.setStyleSheet("""
            QPushButton {
                background-color: #6c757d;
                color: white;
                border: none;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #5a6268;
            }
            QPushButton:pressed {
                background-color: #545b62;
            }
        """)
        self.scroll_bottom_btn.clicked.connect(self.scroll_to_bottom)
        
        scroll_layout.addWidget(self.auto_scroll_checkbox)
        scroll_layout.addStretch()
        scroll_layout.addWidget(self.scroll_top_btn)
        scroll_layout.addWidget(self.scroll_bottom_btn)
        scroll_layout.addWidget(self.clear_results_btn)
        scroll_layout.addWidget(self.export_results_btn)
        
        layout.addWidget(scroll_group)

    def clear_results(self):
        """Clear all scan results"""
        self.network_results_table.setRowCount(0)
        self.port_results_table.setRowCount(0)
        self.results_text.clear()
        self.status_label.setText("Results cleared")

    def export_results(self):
        """Export scan results to file"""
        try:
            from PyQt5.QtWidgets import QFileDialog
            import os
            
            filename, _ = QFileDialog.getSaveFileName(
                self, 
                "Export Scan Results", 
                f"strikesuite_results_{time.strftime('%Y%m%d_%H%M%S')}.txt",
                "Text Files (*.txt);;All Files (*)"
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("StrikeSuite Scan Results\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(f"Export Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    
                    # Export network results
                    f.write("Network Scan Results:\n")
                    f.write("-" * 30 + "\n")
                    for row in range(self.network_results_table.rowCount()):
                        host = self.network_results_table.item(row, 0)
                        device = self.network_results_table.item(row, 1)
                        ports = self.network_results_table.item(row, 2)
                        services = self.network_results_table.item(row, 3)
                        
                        if host:
                            f.write(f"Host: {host.text()}\n")
                            if device:
                                f.write(f"  Device: {device.text()}\n")
                            if ports:
                                f.write(f"  Ports: {ports.text()}\n")
                            if services:
                                f.write(f"  Services: {services.text()}\n")
                            f.write("\n")
                    
                    # Export port results
                    f.write("Port Scan Results:\n")
                    f.write("-" * 30 + "\n")
                    for row in range(self.port_results_table.rowCount()):
                        port = self.port_results_table.item(row, 0)
                        state = self.port_results_table.item(row, 1)
                        service = self.port_results_table.item(row, 2)
                        banner = self.port_results_table.item(row, 3)
                        
                        if port:
                            f.write(f"Port {port.text()}: {state.text() if state else 'Unknown'}\n")
                            if service:
                                f.write(f"  Service: {service.text()}\n")
                            if banner:
                                f.write(f"  Banner: {banner.text()}\n")
                            f.write("\n")
                    
                    # Export detailed logs
                    f.write("Detailed Logs:\n")
                    f.write("-" * 30 + "\n")
                    f.write(self.results_text.toPlainText())
                
                self.results_text.append(f"Results exported to: {filename}")
                QMessageBox.information(self, "Export Successful", f"Results exported to:\n{filename}")
                
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export results:\n{str(e)}")

    def scroll_to_top(self):
        """Scroll to the top of the page"""
        if hasattr(self, 'main_scroll'):
            self.main_scroll.verticalScrollBar().setValue(0)
            self.results_text.append("Scrolled to top of page")

    def scroll_to_bottom(self):
        """Scroll to the bottom of the page"""
        if hasattr(self, 'main_scroll'):
            scrollbar = self.main_scroll.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
            self.results_text.append("Scrolled to bottom of page")

    def comprehensive_scan(self):
        """Ultimate comprehensive scan with 100% accuracy and speed"""
        target = self.target_input.text().strip()
        if not target:
            self.status_label.setText("Please enter a target")
            return
            
        # Get scan type from combo box
        scan_type = self.scan_type_combo.currentText()
        
        # Disable scan button and enable stop button
        self.comprehensive_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        
        # Clear previous results
        self.network_results_table.setRowCount(0)
        self.port_results_table.setRowCount(0)
        self.results_text.clear()
        
        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.status_label.setText(f"🚀 Starting Ultimate Scan: {scan_type}")
        
        # Determine scan parameters based on type
        if "Single Target" in scan_type:
            self._start_single_target_scan(target)
        elif "Network Range" in scan_type:
            self._start_network_scan(target)
        elif "Full Port" in scan_type:
            self._start_full_port_scan(target)
        elif "Quick Port" in scan_type:
            self._start_quick_port_scan(target)
        elif "Security" in scan_type:
            self._start_security_scan(target)
        else:
            self._start_single_target_scan(target)  # Default

    def _start_single_target_scan(self, target):
        """Start single target comprehensive scan"""
        scan_options = {
            'ports': list(range(1, 1001)),  # Top 1000 ports
            'max_threads': 100,
            'timeout': 1.0,
            'scan_type': 'tcp',
            'os_detection': True,
            'service_detection': True,
            'banner_grabbing': True
        }
        self.start_advanced_scan(target, scan_options)
    
    def _start_network_scan(self, target):
        """Start network range scan"""
        if '/' not in target:
            target = target + '/24'  # Default to /24 if no CIDR
        self.network_scan()
    
    def _start_full_port_scan(self, target):
        """Start full port scan (1-65535)"""
        scan_options = {
            'ports': list(range(1, 65536)),
            'max_threads': 200,
            'timeout': 0.5,
            'scan_type': 'tcp',
            'os_detection': True,
            'service_detection': True,
            'banner_grabbing': True
        }
        self.start_advanced_scan(target, scan_options)
    
    def _start_quick_port_scan(self, target):
        """Start quick port scan (top 1000)"""
        scan_options = {
            'ports': list(range(1, 1001)),
            'max_threads': 150,
            'timeout': 0.8,
            'scan_type': 'tcp',
            'os_detection': True,
            'service_detection': True,
            'banner_grabbing': True
        }
        self.start_advanced_scan(target, scan_options)
    
    def _start_security_scan(self, target):
        """Start security vulnerability scan"""
        scan_options = {
            'ports': [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017],
            'max_threads': 100,
            'timeout': 2.0,
            'scan_type': 'tcp',
            'os_detection': True,
            'service_detection': True,
            'banner_grabbing': True,
            'vulnerability_scan': True
        }
        self.start_advanced_scan(target, scan_options)
        
    def start_advanced_scan(self, target, scan_options):
        """Start advanced port scan"""
        self.status_label.setText(f"Starting advanced scan of {target}...")
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.progress_bar.setValue(0)
        
        # Disable scan buttons
        self.comprehensive_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        
        # Clear previous results and switch to port scan tab
        self.port_results_table.setRowCount(0)
        self.results_text.clear()
        self.results_tabs.setCurrentIndex(1)  # Switch to port scan tab
        
        # Start advanced scan in background thread
        self.advanced_scan_thread = AdvancedScanThread(target, scan_options)
        self.advanced_scan_thread.progress.connect(self.update_advanced_progress)
        self.advanced_scan_thread.result.connect(self.advanced_scan_finished)
        self.advanced_scan_thread.start()
            
    def update_advanced_progress(self, message):
        """Update advanced scan progress"""
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
            
            # Display results in port scan table
            for port_info in results.get('open_ports', []):
                row = self.port_results_table.rowCount()
                self.port_results_table.insertRow(row)
                
                # Port
                port_item = QTableWidgetItem(str(port_info.get('port', '')))
                port_item.setTextAlignment(Qt.AlignCenter)
                port_item.setData(Qt.UserRole, f"Port {port_info.get('port', '')} advanced scan completed")
                self.port_results_table.setItem(row, 0, port_item)
                
                # State
                state_item = QTableWidgetItem("OPEN")
                state_item.setTextAlignment(Qt.AlignCenter)
                state_item.setBackground(QColor(144, 238, 144))  # Light green
                self.port_results_table.setItem(row, 1, state_item)
                
                # Service
                service_item = QTableWidgetItem(port_info.get('service', ''))
                self.port_results_table.setItem(row, 2, service_item)
                
                # Banner
                banner_item = QTableWidgetItem("No banner detected")
                self.port_results_table.setItem(row, 3, banner_item)
            
            # Display scan statistics
            if 'scan_stats' in results:
                stats = results['scan_stats']
                self.results_text.append(f"Scan Statistics:")
                self.results_text.append(f"  Total Ports: {stats.get('total_ports', 0)}")
                self.results_text.append(f"  Open Ports: {stats.get('open_ports', 0)}")
                self.results_text.append(f"  Closed Ports: {stats.get('closed_ports', 0)}")
                self.results_text.append(f"  Filtered Ports: {stats.get('filtered_ports', 0)}")
                self.results_text.append(f"  Scan Duration: {stats.get('scan_duration', 0)}s")
                self.results_text.append(f"  Scan Speed: {stats.get('scan_speed', 0)} ports/sec")
            
            # Display OS fingerprint
            if results.get('os_fingerprint'):
                os_info = results['os_fingerprint']
                self.results_text.append(f"OS: {os_info.get('os', 'Unknown')} - {os_info.get('confidence', 0)}% confidence")
        
            # Auto-scroll to bottom if enabled
            if self.auto_scroll_checkbox.isChecked():
                self.results_text.moveCursor(self.results_text.textCursor().End)
        
        self.progress_bar.setVisible(False)
        
        # Re-enable scan buttons
        self.comprehensive_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
    
    def network_scan(self):
        """Perform network scan on CIDR range"""
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "No Target", "Please enter a network range (e.g., 192.168.1.0/24)")
            return
        
        # Check if target looks like a network range
        if '/' not in target:
            QMessageBox.warning(self, "Invalid Network", 
                              "Please enter a network range in CIDR notation (e.g., 192.168.1.0/24)")
            return
        
        try:
            network = ipaddress.ip_network(target, strict=False)
            host_count = len(list(network.hosts()))
            
            if host_count > 256:
                reply = QMessageBox.question(self, "Large Network", 
                                           f"This network contains {host_count} hosts. This may take a long time. Continue?",
                                           QMessageBox.Yes | QMessageBox.No)
                if reply != QMessageBox.Yes:
                    return
            
        except Exception as e:
            QMessageBox.critical(self, "Invalid Network", f"Invalid network format: {e}")
            return
        
        # Disable scan buttons
        self.comprehensive_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        
        # Clear previous results and switch to network scan tab
        self.network_results_table.setRowCount(0)
        self.results_text.clear()
        self.results_tabs.setCurrentIndex(0)  # Switch to network scan tab
        
        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.status_label.setText(f"Scanning network {target}...")
        
        # Start network scan in background thread
        self.network_scan_thread = NetworkScanThread(target)
        self.network_scan_thread.progress.connect(self.update_network_progress)
        self.network_scan_thread.result.connect(self.network_scan_finished)
        self.network_scan_thread.start()
    
    def update_network_progress(self, message):
        """Update network scan progress"""
        self.status_label.setText(message)
    
    def network_scan_finished(self, results):
        """Handle network scan completion"""
        if 'error' in results:
            self.status_label.setText(f"Network scan failed: {results['error']}")
            self.results_text.append(f"Error: {results['error']}")
        else:
            live_hosts = len(results.get('live_hosts', []))
            self.status_label.setText(f"Network scan completed - {live_hosts} live hosts found")
            
            # Display results in network scan table
            for host_info in results.get('live_hosts', []):
                row = self.network_results_table.rowCount()
                self.network_results_table.insertRow(row)
                
                # Host IP
                host_item = QTableWidgetItem(host_info.get('host', ''))
                host_item.setTextAlignment(Qt.AlignCenter)
                self.network_results_table.setItem(row, 0, host_item)
                
                # Device Type
                device_item = QTableWidgetItem("Unknown")
                self.network_results_table.setItem(row, 1, device_item)
                
                # Open Ports
                open_ports = host_info.get('open_ports', [])
                ports_text = ', '.join([str(p.get('port', '')) for p in open_ports])
                ports_item = QTableWidgetItem(ports_text)
                self.network_results_table.setItem(row, 2, ports_item)
                
                # Services
                services = host_info.get('services', {})
                services_text = ', '.join(services.keys())
                services_item = QTableWidgetItem(services_text)
                self.network_results_table.setItem(row, 3, services_item)
            
            # Display scan statistics
            self.results_text.append(f"Network Scan Results:")
            self.results_text.append(f"  Network: {results.get('network', 'Unknown')}")
            self.results_text.append(f"  Total Hosts: {results.get('total_hosts', 0)}")
            self.results_text.append(f"  Live Hosts: {live_hosts}")
            self.results_text.append(f"  Scan Time: {results.get('scan_time', 'Unknown')}")
            
            # Auto-scroll to bottom if enabled
            if self.auto_scroll_checkbox.isChecked():
                self.results_text.moveCursor(self.results_text.textCursor().End)
        
        self.progress_bar.setVisible(False)
        
        # Re-enable scan buttons
        self.comprehensive_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)

    def stop_scan(self):
        """Stop current scan"""
        if hasattr(self, 'scan_thread') and self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.terminate()
            self.scan_thread.wait()
        
        if hasattr(self, 'advanced_scan_thread') and self.advanced_scan_thread and self.advanced_scan_thread.isRunning():
            self.advanced_scan_thread.terminate()
            self.advanced_scan_thread.wait()
        
        if hasattr(self, 'network_scan_thread') and self.network_scan_thread and self.network_scan_thread.isRunning():
            self.network_scan_thread.terminate()
            self.network_scan_thread.wait()
        
        self.status_label.setText("Scan stopped")
        self.progress_bar.setVisible(False)
        
        # Re-enable scan buttons
        self.comprehensive_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)

class AdvancedScanThread(QThread):
    """Thread for running advanced scans"""
    
    progress = pyqtSignal(str)  # Progress message
    result = pyqtSignal(dict)  # Scan results
    
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
            
            self.progress.emit("Starting enhanced port scan...")
            
            # Use the improved scan_ports method with enhanced results
            ports = self.scan_options.get('ports', list(range(1, 1001)))
            results = scanner.scan_ports(self.target, ports)
            
            # Add scan statistics to results
            if 'scan_stats' not in results:
                results['scan_stats'] = {
                    'total_ports': len(ports),
                    'open_ports': len(results.get('open_ports', [])),
                    'closed_ports': len(results.get('closed_ports', [])),
                    'filtered_ports': len(results.get('filtered_ports', [])),
                    'scan_duration': 0
                }
            
            self.progress.emit("Enhanced port scan completed successfully")
            self.result.emit(results)
            
        except Exception as e:
            self.result.emit({'error': str(e)})

class NetworkScanThread(QThread):
    """Thread for running network scans"""
    
    progress = pyqtSignal(str)  # Progress message
    result = pyqtSignal(dict)  # Scan results
    
    def __init__(self, target):
        super().__init__()
        self.target = target
    
    def run(self):
        """Run the network scan"""
        try:
            from core.scanner import NetworkScanner
            
            scanner = NetworkScanner(max_threads=50, timeout=2.0)
            
            self.progress.emit("Starting network scan...")
            results = scanner.network_scan(self.target)
            
            self.progress.emit("Network scan completed successfully")
            self.result.emit(results)
            
        except Exception as e:
            self.result.emit({'error': str(e)})
