#!/usr/bin/env python3
"""
Brute Force Tab
GUI for brute force testing functionality
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QLineEdit, QPushButton, QTextEdit,
                             QCheckBox, QGroupBox, QTableWidget, QTableWidgetItem,
                             QHeaderView, QSpinBox, QComboBox, QScrollArea,
                             QFileDialog, QListWidget, QListWidgetItem, QTabWidget)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import time

# Import core modules
import sys
from pathlib import Path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

class BruteForceTab(QWidget):
    """Brute force testing tab widget"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface with modern design and full page scrolling"""
        # Create main scroll area for the entire page
        self.main_scroll = QScrollArea()
        self.main_scroll.setWidgetResizable(True)
        self.main_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.main_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.main_scroll.setStyleSheet("""
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
                background-color: #e74c3c;
                border-radius: 8px;
                min-height: 30px;
                margin: 2px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #c0392b;
            }
            QScrollBar::handle:vertical:pressed {
                background-color: #a93226;
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
                background-color: #e74c3c;
                border-radius: 8px;
                min-width: 30px;
                margin: 2px;
            }
            QScrollBar::handle:horizontal:hover {
                background-color: #c0392b;
            }
            QScrollBar::handle:horizontal:pressed {
                background-color: #a93226;
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
        
        # Set the main widget in scroll area
        self.main_scroll.setWidget(main_widget)
        
        # Create main layout for the widget
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(self.main_scroll)
        
        # Create content layout inside the main widget
        layout = QVBoxLayout(main_widget)
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Add welcome section
        self.create_welcome_section(layout)
        
        # Set up keyboard shortcuts for scrolling
        self.setup_keyboard_shortcuts()
        
        # Target configuration
        target_group = QGroupBox("Target Configuration")
        target_layout = QGridLayout(target_group)
        
        target_layout.addWidget(QLabel("Target IP/Hostname:"), 0, 0)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("192.168.1.1 or example.com")
        target_layout.addWidget(self.target_input, 0, 1)
        
        target_layout.addWidget(QLabel("Port:"), 1, 0)
        self.port_input = QLineEdit()
        self.port_input.setText("22")
        self.port_input.setPlaceholderText("22, 21, 23, 80")
        target_layout.addWidget(self.port_input, 1, 1)
        
        target_layout.addWidget(QLabel("Service:"), 2, 0)
        self.service_combo = QComboBox()
        self.service_combo.addItems(["SSH", "FTP", "HTTP", "Telnet", "MySQL", "PostgreSQL", "MSSQL"])
        target_layout.addWidget(self.service_combo, 2, 1)
        
        layout.addWidget(target_group)
        
        # Credential options
        creds_group = QGroupBox("Credential Options")
        creds_layout = QVBoxLayout(creds_group)
        
        # Username options
        username_layout = QHBoxLayout()
        username_layout.addWidget(QLabel("Username:"))
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("admin, root, user")
        username_layout.addWidget(self.username_input)
        creds_layout.addLayout(username_layout)
        
        # Password options
        password_layout = QHBoxLayout()
        password_layout.addWidget(QLabel("Password:"))
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("password, 123456, admin")
        password_layout.addWidget(self.password_input)
        creds_layout.addLayout(password_layout)
        
        # Use wordlists
        self.use_wordlists_check = QCheckBox("Use built-in wordlists")
        self.use_wordlists_check.setChecked(True)
        creds_layout.addWidget(self.use_wordlists_check)
        
        # File selection options
        file_selection_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout(file_selection_group)
        
        # Username file selection
        username_file_layout = QHBoxLayout()
        username_file_label = QLabel("Username File:")
        username_file_layout.addWidget(username_file_label)
        
        self.username_file_input = QLineEdit()
        self.username_file_input.setPlaceholderText("Select username wordlist file...")
        username_file_layout.addWidget(self.username_file_input)
        
        self.username_file_btn = QPushButton("Browse")
        self.username_file_btn.clicked.connect(self.select_username_file)
        username_file_layout.addWidget(self.username_file_btn)
        
        file_layout.addLayout(username_file_layout)
        
        # Password file selection
        password_file_layout = QHBoxLayout()
        password_file_label = QLabel("Password File:")
        password_file_layout.addWidget(password_file_label)
        
        self.password_file_input = QLineEdit()
        self.password_file_input.setPlaceholderText("Select password wordlist file...")
        password_file_layout.addWidget(self.password_file_input)
        
        self.password_file_btn = QPushButton("Browse")
        self.password_file_btn.clicked.connect(self.select_password_file)
        password_file_layout.addWidget(self.password_file_btn)
        
        file_layout.addLayout(password_file_layout)
        
        # Custom wordlist files
        custom_files_layout = QHBoxLayout()
        custom_files_label = QLabel("Custom Files:")
        custom_files_layout.addWidget(custom_files_label)
        
        self.custom_files_btn = QPushButton("Add Files")
        self.custom_files_btn.clicked.connect(self.add_custom_files)
        custom_files_layout.addWidget(self.custom_files_btn)
        
        self.clear_files_btn = QPushButton("Clear All")
        self.clear_files_btn.clicked.connect(self.clear_custom_files)
        custom_files_layout.addWidget(self.clear_files_btn)
        
        file_layout.addLayout(custom_files_layout)
        
        # Selected files list
        self.selected_files_list = QListWidget()
        self.selected_files_list.setMaximumHeight(100)
        file_layout.addWidget(QLabel("Selected Files:"))
        file_layout.addWidget(self.selected_files_list)
        
        creds_layout.addWidget(file_selection_group)
        
        layout.addWidget(creds_group)
        
        # Advanced brute force options
        advanced_group = QGroupBox("Advanced Brute Force Options")
        advanced_layout = QGridLayout(advanced_group)
        
        # Attack technique
        advanced_layout.addWidget(QLabel("Attack Technique:"), 0, 0)
        self.technique_combo = QComboBox()
        self.technique_combo.addItems(["Intelligent", "Dictionary", "Hybrid", "Mask", "Rule-based"])
        advanced_layout.addWidget(self.technique_combo, 0, 1)
        
        # Attack mode
        advanced_layout.addWidget(QLabel("Attack Mode:"), 1, 0)
        self.attack_mode_combo = QComboBox()
        self.attack_mode_combo.addItems(["Normal", "Stealth", "Aggressive", "Custom"])
        advanced_layout.addWidget(self.attack_mode_combo, 1, 1)
        
        # Wordlist category
        advanced_layout.addWidget(QLabel("Wordlist Category:"), 2, 0)
        self.wordlist_combo = QComboBox()
        self.wordlist_combo.addItems(["Common", "Defaults", "Technical", "Seasonal", "Company", "Brute Force"])
        advanced_layout.addWidget(self.wordlist_combo, 2, 1)
        
        # Pattern matching
        self.pattern_matching_check = QCheckBox("Pattern Matching")
        self.pattern_matching_check.setChecked(True)
        advanced_layout.addWidget(self.pattern_matching_check, 3, 0)
        
        # Rate limit detection
        self.rate_limit_check = QCheckBox("Rate Limit Detection")
        self.rate_limit_check.setChecked(True)
        advanced_layout.addWidget(self.rate_limit_check, 3, 1)
        
        # Database brute force
        self.database_brute_check = QCheckBox("Database Brute Force")
        self.database_brute_check.setChecked(False)
        advanced_layout.addWidget(self.database_brute_check, 4, 0)
        
        # Vulnerability analysis
        self.vuln_analysis_check = QCheckBox("Vulnerability Analysis")
        self.vuln_analysis_check.setChecked(True)
        advanced_layout.addWidget(self.vuln_analysis_check, 4, 1)
        
        layout.addWidget(advanced_group)
        
        # Brute force options
        options_group = QGroupBox("Brute Force Options")
        options_layout = QVBoxLayout(options_group)
        
        # Thread count
        thread_layout = QHBoxLayout()
        thread_layout.addWidget(QLabel("Threads:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 100)
        self.threads_spin.setValue(10)
        thread_layout.addWidget(self.threads_spin)
        thread_layout.addStretch()
        options_layout.addLayout(thread_layout)
        
        # Timeout
        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Timeout (seconds):"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(5)
        timeout_layout.addWidget(self.timeout_spin)
        timeout_layout.addStretch()
        options_layout.addLayout(timeout_layout)
        
        # Delay between attempts
        delay_layout = QHBoxLayout()
        delay_layout.addWidget(QLabel("Delay (seconds):"))
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 10)
        self.delay_spin.setValue(1)
        delay_layout.addWidget(self.delay_spin)
        delay_layout.addStretch()
        options_layout.addLayout(delay_layout)
        
        # Max attempts
        max_attempts_layout = QHBoxLayout()
        max_attempts_layout.addWidget(QLabel("Max Attempts:"))
        self.max_attempts_spin = QSpinBox()
        self.max_attempts_spin.setRange(100, 10000)
        self.max_attempts_spin.setValue(1000)
        max_attempts_layout.addWidget(self.max_attempts_spin)
        max_attempts_layout.addStretch()
        options_layout.addLayout(max_attempts_layout)
        
        layout.addWidget(options_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        # Main comprehensive brute force button
        self.comprehensive_brute_btn = QPushButton("🚀 START COMPREHENSIVE BRUTE FORCE")
        self.comprehensive_brute_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 15px 30px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 8px;
                min-width: 250px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
            QPushButton:pressed {
                background-color: #a93226;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
                color: #7f8c8d;
            }
        """)
        self.comprehensive_brute_btn.clicked.connect(self.start_comprehensive_brute_force)
        button_layout.addWidget(self.comprehensive_brute_btn)
        
        # Individual attack buttons
        self.start_brute_btn = QPushButton("🔐 Standard Attack")
        self.start_brute_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px 20px;
                font-size: 12px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #21618c;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
                color: #7f8c8d;
            }
        """)
        self.start_brute_btn.clicked.connect(self.start_brute_force)
        button_layout.addWidget(self.start_brute_btn)
        
        self.advanced_brute_btn = QPushButton("⚡ Advanced Attack")
        self.advanced_brute_btn.setStyleSheet("""
            QPushButton {
                background-color: #9b59b6;
                color: white;
                border: none;
                padding: 10px 20px;
                font-size: 12px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #8e44ad;
            }
            QPushButton:pressed {
                background-color: #7d3c98;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
                color: #7f8c8d;
            }
        """)
        self.advanced_brute_btn.clicked.connect(self.start_advanced_brute_force)
        button_layout.addWidget(self.advanced_brute_btn)
        
        self.stop_brute_btn = QPushButton("⏹️ STOP ATTACK")
        self.stop_brute_btn.setEnabled(False)
        self.stop_brute_btn.setStyleSheet("""
            QPushButton {
                background-color: #e67e22;
                color: white;
                border: none;
                padding: 10px 20px;
                font-size: 12px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #d35400;
            }
            QPushButton:pressed {
                background-color: #ba4a00;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
                color: #7f8c8d;
            }
        """)
        self.stop_brute_btn.clicked.connect(self.stop_brute_force)
        button_layout.addWidget(self.stop_brute_btn)
        
        layout.addLayout(button_layout)
        
        # Results section with enhanced display
        results_group = QGroupBox("🔍 COMPREHENSIVE BRUTE FORCE RESULTS")
        results_layout = QVBoxLayout(results_group)
        
        # Create tab widget for different result types
        self.results_tabs = QTabWidget()
        results_layout.addWidget(self.results_tabs)
        
        # Credentials Found Tab
        credentials_tab = QWidget()
        credentials_layout = QVBoxLayout(credentials_tab)
        
        # Results table with enhanced display
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["Service", "Username", "Password", "Status", "Timestamp"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        # Set minimum rows to show 10 results
        self.results_table.setRowCount(10)
        self.results_table.setMinimumHeight(300)
        self.results_table.setMaximumHeight(500)
        
        # Initialize empty rows with placeholder text
        for row in range(10):
            for col in range(5):
                item = QTableWidgetItem("")
                if col == 0:  # Service column
                    item.setText("---")
                elif col == 1:  # Username column
                    item.setText("---")
                elif col == 2:  # Password column
                    item.setText("---")
                elif col == 3:  # Status column
                    item.setText("---")
                elif col == 4:  # Timestamp column
                    item.setText("---")
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)  # Make read-only
                self.results_table.setItem(row, col, item)
        
        credentials_layout.addWidget(self.results_table)
        self.results_tabs.addTab(credentials_tab, "🔐 Found Credentials")
        
        # Attack Statistics Tab
        stats_tab = QWidget()
        stats_layout = QVBoxLayout(stats_tab)
        
        self.stats_table = QTableWidget()
        self.stats_table.setColumnCount(3)
        self.stats_table.setHorizontalHeaderLabels(["Attack Type", "Attempts", "Success Rate"])
        self.stats_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.stats_table.setRowCount(8)
        self.stats_table.setMinimumHeight(200)
        
        # Initialize stats table
        attack_types = ["SSH Attack", "FTP Attack", "HTTP Attack", "MySQL Attack", 
                       "PostgreSQL Attack", "MSSQL Attack", "MongoDB Attack", "Redis Attack"]
        for row, attack_type in enumerate(attack_types):
            self.stats_table.setItem(row, 0, QTableWidgetItem(attack_type))
            self.stats_table.setItem(row, 1, QTableWidgetItem("0"))
            self.stats_table.setItem(row, 2, QTableWidgetItem("0%"))
        
        stats_layout.addWidget(self.stats_table)
        self.results_tabs.addTab(stats_tab, "📊 Attack Statistics")
        
        # Vulnerabilities Tab
        vuln_tab = QWidget()
        vuln_layout = QVBoxLayout(vuln_tab)
        
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(4)
        self.vuln_table.setHorizontalHeaderLabels(["Vulnerability", "Severity", "Description", "Recommendation"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.vuln_table.setRowCount(5)
        self.vuln_table.setMinimumHeight(200)
        
        vuln_layout.addWidget(self.vuln_table)
        self.results_tabs.addTab(vuln_tab, "🛡️ Security Vulnerabilities")
        
        # Results text with enhanced scrolling
        self.results_text = QTextEdit()
        self.results_text.setMaximumHeight(200)
        self.results_text.setMinimumHeight(150)
        self.results_text.setPlaceholderText("Comprehensive brute force attack results and logs will appear here...")
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
                border-color: #3498db;
            }
        """)
        results_layout.addWidget(self.results_text)
        
        # Export and control buttons
        export_layout = QHBoxLayout()
        
        self.export_results_btn = QPushButton("📤 Export Results")
        self.export_results_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #229954;
            }
        """)
        self.export_results_btn.clicked.connect(self.export_results)
        export_layout.addWidget(self.export_results_btn)
        
        self.clear_results_btn = QPushButton("🗑️ Clear Results")
        self.clear_results_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        self.clear_results_btn.clicked.connect(self.clear_results)
        export_layout.addWidget(self.clear_results_btn)
        
        # Page scroll controls
        self.scroll_to_top_btn = QPushButton("⬆️ Scroll to Top")
        self.scroll_to_top_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        self.scroll_to_top_btn.clicked.connect(self.scroll_to_top)
        export_layout.addWidget(self.scroll_to_top_btn)
        
        self.scroll_to_bottom_btn = QPushButton("⬇️ Scroll to Bottom")
        self.scroll_to_bottom_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        self.scroll_to_bottom_btn.clicked.connect(self.scroll_to_bottom)
        export_layout.addWidget(self.scroll_to_bottom_btn)
        
        # Auto-scroll checkbox
        self.auto_scroll_checkbox = QCheckBox("Auto-scroll to bottom")
        self.auto_scroll_checkbox.setChecked(True)
        self.auto_scroll_checkbox.setStyleSheet("""
            QCheckBox {
                font-weight: bold;
                color: #2c3e50;
                padding: 5px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
            }
            QCheckBox::indicator:checked {
                background-color: #3498db;
                border: 2px solid #3498db;
                border-radius: 3px;
            }
        """)
        export_layout.addWidget(self.auto_scroll_checkbox)
        
        export_layout.addStretch()
        results_layout.addLayout(export_layout)
        
        layout.addWidget(results_group)
        
    def start_comprehensive_brute_force(self):
        """Start comprehensive brute force attack with all features"""
        target = self.target_input.text().strip()
        if not target:
            self.results_text.append("❌ Please enter a target IP or hostname")
            return
        
        # Disable all buttons and enable stop button
        self.comprehensive_brute_btn.setEnabled(False)
        self.start_brute_btn.setEnabled(False)
        self.advanced_brute_btn.setEnabled(False)
        self.stop_brute_btn.setEnabled(True)
        
        # Clear previous results
        self.clear_results()
        
        # Show comprehensive attack start message
        self.results_text.append("🚀 STARTING COMPREHENSIVE BRUTE FORCE ATTACK")
        self.results_text.append("=" * 60)
        self.results_text.append(f"🎯 Target: {target}")
        self.results_text.append(f"⏰ Start Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.results_text.append("")
        
        # Start comprehensive brute force in background thread
        self.comprehensive_thread = ComprehensiveBruteForceThread(target, self.get_comprehensive_options())
        self.comprehensive_thread.progress.connect(self.update_comprehensive_progress)
        self.comprehensive_thread.result.connect(self.comprehensive_brute_finished)
        self.comprehensive_thread.start()
        
    def get_comprehensive_options(self):
        """Get comprehensive brute force options"""
        return {
            'port': int(self.port_input.text()) if self.port_input.text().isdigit() else 22,
            'service': self.service_combo.currentText().lower(),
            'username': self.username_input.text().strip(),
            'password': self.password_input.text().strip(),
            'use_wordlists': self.use_wordlists_check.isChecked(),
            'username_file': self.username_file_input.text().strip(),
            'password_file': self.password_file_input.text().strip(),
            'custom_files': self.get_selected_files(),
            'threads': self.threads_spin.value(),
            'timeout': self.timeout_spin.value(),
            'delay': self.delay_spin.value(),
            'max_attempts': self.max_attempts_spin.value(),
            'technique': self.technique_combo.currentText().lower().replace('-', '_'),
            'attack_mode': self.attack_mode_combo.currentText().lower(),
            'wordlist_category': self.wordlist_combo.currentText().lower(),
            'pattern_matching': self.pattern_matching_check.isChecked(),
            'rate_limit_detection': self.rate_limit_check.isChecked(),
            'database_brute_force': self.database_brute_check.isChecked(),
            'vulnerability_analysis': self.vuln_analysis_check.isChecked(),
            'comprehensive_mode': True
        }
        
    def update_comprehensive_progress(self, message):
        """Update comprehensive brute force progress"""
        self.results_text.append(f"📊 {message}")
        # Auto-scroll to bottom if enabled
        if self.auto_scroll_checkbox.isChecked():
            self.results_text.moveCursor(self.results_text.textCursor().End)
            # Also scroll the main page to bottom
            self.scroll_to_bottom()
        
    def comprehensive_brute_finished(self, results):
        """Handle comprehensive brute force completion"""
        # Re-enable buttons
        self.comprehensive_brute_btn.setEnabled(True)
        self.start_brute_btn.setEnabled(True)
        self.advanced_brute_btn.setEnabled(True)
        self.stop_brute_btn.setEnabled(False)
        
        if 'error' in results:
            self.results_text.append(f"❌ Comprehensive attack failed: {results['error']}")
            return
        
        # Display comprehensive results
        self.results_text.append("")
        self.results_text.append("🎉 COMPREHENSIVE BRUTE FORCE ATTACK COMPLETED!")
        self.results_text.append("=" * 60)
        
        # Display found credentials
        found_credentials = results.get('found_credentials', [])
        if found_credentials:
            self.results_text.append(f"✅ Found {len(found_credentials)} valid credentials:")
            for cred in found_credentials:
                self.results_text.append(f"   🔐 {cred.get('service', 'Unknown')}: {cred.get('username', '')}:{cred.get('password', '')}")
                self._add_credential_to_table(cred)
        else:
            self.results_text.append("❌ No valid credentials found")
        
        # Display attack statistics
        stats = results.get('attack_stats', {})
        if stats:
            self.results_text.append("")
            self.results_text.append("📊 ATTACK STATISTICS:")
            self.results_text.append(f"   Total Attempts: {stats.get('total_attempts', 0)}")
            self.results_text.append(f"   Successful: {stats.get('successful_attempts', 0)}")
            self.results_text.append(f"   Failed: {stats.get('failed_attempts', 0)}")
            self.results_text.append(f"   Rate Limited: {stats.get('rate_limited', 0)}")
            self.results_text.append(f"   Connection Errors: {stats.get('connection_errors', 0)}")
            
            # Update statistics table
            self._update_stats_table(stats)
        
        # Display vulnerabilities
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            self.results_text.append("")
            self.results_text.append("🛡️ SECURITY VULNERABILITIES FOUND:")
            for vuln in vulnerabilities:
                self.results_text.append(f"   ⚠️ {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}")
                self.results_text.append(f"      {vuln.get('description', '')}")
                self._add_vulnerability_to_table(vuln)
        
        # Display recommendations
        recommendations = results.get('recommendations', [])
        if recommendations:
            self.results_text.append("")
            self.results_text.append("💡 SECURITY RECOMMENDATIONS:")
            for rec in recommendations:
                self.results_text.append(f"   • {rec}")
        
        self.results_text.append("")
        self.results_text.append("🏁 Comprehensive brute force attack completed successfully!")
        
    def _add_credential_to_table(self, credential):
        """Add found credential to results table"""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        self.results_table.setItem(row, 0, QTableWidgetItem(credential.get('service', 'Unknown')))
        self.results_table.setItem(row, 1, QTableWidgetItem(credential.get('username', '')))
        self.results_table.setItem(row, 2, QTableWidgetItem(credential.get('password', '')))
        self.results_table.setItem(row, 3, QTableWidgetItem("SUCCESS"))
        self.results_table.setItem(row, 4, QTableWidgetItem(credential.get('timestamp', '')))
        
    def _update_stats_table(self, stats):
        """Update attack statistics table"""
        # This would be implemented to show detailed stats per attack type
        pass
        
    def _add_vulnerability_to_table(self, vulnerability):
        """Add vulnerability to vulnerabilities table"""
        row = self.vuln_table.rowCount()
        self.vuln_table.insertRow(row)
        
        self.vuln_table.setItem(row, 0, QTableWidgetItem(vulnerability.get('type', 'Unknown')))
        self.vuln_table.setItem(row, 1, QTableWidgetItem(vulnerability.get('severity', 'Unknown')))
        self.vuln_table.setItem(row, 2, QTableWidgetItem(vulnerability.get('description', '')))
        self.vuln_table.setItem(row, 3, QTableWidgetItem(vulnerability.get('recommendation', '')))
        
    def clear_results(self):
        """Clear all results"""
        # Clear credentials table
        self.results_table.setRowCount(0)
        self.results_table.setRowCount(10)
        
        # Clear stats table
        for row in range(8):
            self.stats_table.setItem(row, 1, QTableWidgetItem("0"))
            self.stats_table.setItem(row, 2, QTableWidgetItem("0%"))
        
        # Clear vulnerabilities table
        self.vuln_table.setRowCount(0)
        self.vuln_table.setRowCount(5)
        
        # Clear results text
        self.results_text.clear()
        
    def export_results(self):
        """Export comprehensive brute force results"""
        try:
            from PyQt5.QtWidgets import QFileDialog
            import os
            import json
            
            filename, _ = QFileDialog.getSaveFileName(
                self, 
                "Export Brute Force Results", 
                f"strikesuite_brute_force_{time.strftime('%Y%m%d_%H%M%S')}.json",
                "JSON Files (*.json);;Text Files (*.txt);;All Files (*)"
            )
            
            if filename:
                # Collect all results data
                results_data = {
                    'export_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'credentials': [],
                    'statistics': {},
                    'vulnerabilities': [],
                    'logs': self.results_text.toPlainText()
                }
                
                # Export credentials
                for row in range(self.results_table.rowCount()):
                    service = self.results_table.item(row, 0)
                    username = self.results_table.item(row, 1)
                    password = self.results_table.item(row, 2)
                    status = self.results_table.item(row, 3)
                    timestamp = self.results_table.item(row, 4)
                    
                    if service and service.text() != "---":
                        results_data['credentials'].append({
                            'service': service.text(),
                            'username': username.text() if username else '',
                            'password': password.text() if password else '',
                            'status': status.text() if status else '',
                            'timestamp': timestamp.text() if timestamp else ''
                        })
                
                # Export vulnerabilities
                for row in range(self.vuln_table.rowCount()):
                    vuln_type = self.vuln_table.item(row, 0)
                    severity = self.vuln_table.item(row, 1)
                    description = self.vuln_table.item(row, 2)
                    recommendation = self.vuln_table.item(row, 3)
                    
                    if vuln_type and vuln_type.text() != "":
                        results_data['vulnerabilities'].append({
                            'type': vuln_type.text(),
                            'severity': severity.text() if severity else '',
                            'description': description.text() if description else '',
                            'recommendation': recommendation.text() if recommendation else ''
                        })
                
                # Write to file
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(results_data, f, indent=2, ensure_ascii=False)
                
                self.results_text.append(f"📤 Results exported to: {filename}")
                
        except Exception as e:
            self.results_text.append(f"❌ Export failed: {str(e)}")
    
    def scroll_to_top(self):
        """Scroll to the top of the page"""
        if hasattr(self, 'main_scroll'):
            self.main_scroll.verticalScrollBar().setValue(0)
            self.results_text.append("⬆️ Scrolled to top of page")
    
    def scroll_to_bottom(self):
        """Scroll to the bottom of the page"""
        if hasattr(self, 'main_scroll'):
            scrollbar = self.main_scroll.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
            self.results_text.append("⬇️ Scrolled to bottom of page")
        
    def start_brute_force(self):
        """Start brute force attack"""
        target = self.target_input.text().strip()
        if not target:
            self.results_text.append("Please enter a target")
            return
            
        self.start_brute_btn.setEnabled(False)
        self.stop_brute_btn.setEnabled(True)
        
        # Clear previous results
        self.results_table.setRowCount(0)
        self.results_text.clear()
        
        # Start brute force in background thread
        self.brute_thread = BruteForceThread(target, self.get_brute_options())
        self.brute_thread.result.connect(self.brute_finished)
        self.brute_thread.start()
        
    def get_brute_options(self):
        """Get brute force options"""
        return {
            'port': int(self.port_input.text()) if self.port_input.text().isdigit() else 22,
            'service': self.service_combo.currentText().lower(),
            'username': self.username_input.text().strip(),
            'password': self.password_input.text().strip(),
            'use_wordlists': self.use_wordlists_check.isChecked(),
            'username_file': self.username_file_input.text().strip(),
            'password_file': self.password_file_input.text().strip(),
            'custom_files': self.get_selected_files(),
            'threads': self.threads_spin.value(),
            'timeout': self.timeout_spin.value(),
            'delay': self.delay_spin.value()
        }
        
    def get_advanced_brute_options(self):
        """Get advanced brute force options"""
        technique_map = {
            "Intelligent": "intelligent",
            "Dictionary": "dictionary", 
            "Hybrid": "hybrid",
            "Mask": "mask",
            "Rule-based": "rule_based"
        }
        
        attack_mode_map = {
            "Normal": "normal",
            "Stealth": "stealth",
            "Aggressive": "aggressive", 
            "Custom": "custom"
        }
        
        wordlist_map = {
            "Common": "common",
            "Defaults": "defaults",
            "Technical": "technical", 
            "Seasonal": "seasonal",
            "Company": "company",
            "Brute Force": "brute_force"
        }
        
        return {
            'port': int(self.port_input.text()) if self.port_input.text().isdigit() else 22,
            'service': self.service_combo.currentText().lower(),
            'username': self.username_input.text().strip(),
            'password': self.password_input.text().strip(),
            'use_wordlists': self.use_wordlists_check.isChecked(),
            'username_file': self.username_file_input.text().strip(),
            'password_file': self.password_file_input.text().strip(),
            'custom_files': self.get_selected_files(),
            'threads': self.threads_spin.value(),
            'timeout': self.timeout_spin.value(),
            'delay': self.delay_spin.value(),
            'max_attempts': self.max_attempts_spin.value(),
            'technique': technique_map.get(self.technique_combo.currentText(), 'intelligent'),
            'attack_mode': attack_mode_map.get(self.attack_mode_combo.currentText(), 'normal'),
            'wordlist_category': wordlist_map.get(self.wordlist_combo.currentText(), 'common'),
            'pattern_matching': self.pattern_matching_check.isChecked(),
            'rate_limit_detection': self.rate_limit_check.isChecked(),
            'database_brute_force': self.database_brute_check.isChecked(),
            'vulnerability_analysis': self.vuln_analysis_check.isChecked()
        }
        
    def brute_finished(self, results):
        """Handle brute force completion"""
        self.start_brute_btn.setEnabled(True)
        self.advanced_brute_btn.setEnabled(True)
        self.stop_brute_btn.setEnabled(False)
        
        # Display results
        for result in results.get('results', []):
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            
            self.results_table.setItem(row, 0, QTableWidgetItem(result.get('username', '')))
            self.results_table.setItem(row, 1, QTableWidgetItem(result.get('password', '')))
            self.results_table.setItem(row, 2, QTableWidgetItem(result.get('status', '')))
            self.results_table.setItem(row, 3, QTableWidgetItem(result.get('response', '')))
            
            # Add to results text
            status = result.get('status', 'Unknown')
            username = result.get('username', '')
            password = result.get('password', '')
            self.results_text.append(f"{username}:{password} - {status}")
            
    def start_advanced_brute_force(self):
        """Start advanced brute force attack"""
        target = self.target_input.text().strip()
        if not target:
            self.results_text.append("Please enter a target")
            return
            
        self.start_brute_btn.setEnabled(False)
        self.advanced_brute_btn.setEnabled(False)
        self.stop_brute_btn.setEnabled(True)
        
        # Clear previous results
        self.results_table.setRowCount(0)
        self.results_text.clear()
        
        # Start advanced brute force in background thread
        self.brute_thread = AdvancedBruteForceThread(target, self.get_advanced_brute_options())
        self.brute_thread.result.connect(self.advanced_brute_finished)
        self.brute_thread.start()
        
    def advanced_brute_finished(self, results):
        """Handle advanced brute force completion"""
        self.start_brute_btn.setEnabled(True)
        self.advanced_brute_btn.setEnabled(True)
        self.stop_brute_btn.setEnabled(False)
        
        if 'error' in results:
            self.results_text.append(f"Error: {results['error']}")
            return
            
        # Display found credentials
        for credential in results.get('found_credentials', []):
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            
            self.results_table.setItem(row, 0, QTableWidgetItem(credential.get('username', '')))
            self.results_table.setItem(row, 1, QTableWidgetItem(credential.get('password', '')))
            self.results_table.setItem(row, 2, QTableWidgetItem("SUCCESS"))
            self.results_table.setItem(row, 3, QTableWidgetItem(credential.get('response', '')))
            
            # Add to results text
            username = credential.get('username', '')
            password = credential.get('password', '')
            self.results_text.append(f"FOUND: {username}:{password}")
        
        # Display attack statistics
        stats = results.get('attack_stats', {})
        if stats:
            self.results_text.append(f"\nAttack Statistics:")
            self.results_text.append(f"Total Attempts: {stats.get('total_attempts', 0)}")
            self.results_text.append(f"Successful: {stats.get('successful_attempts', 0)}")
            self.results_text.append(f"Failed: {stats.get('failed_attempts', 0)}")
            self.results_text.append(f"Rate Limited: {stats.get('rate_limited', 0)}")
        
        # Display vulnerabilities
        for vuln in results.get('vulnerabilities', []):
            self.results_text.append(f"VULNERABILITY: {vuln.get('type', '')} - {vuln.get('description', '')}")
        
        # Display recommendations
        for rec in results.get('recommendations', []):
            self.results_text.append(f"RECOMMENDATION: {rec}")
            
    def stop_brute_force(self):
        """Stop current brute force"""
        if hasattr(self, 'brute_thread') and self.brute_thread.isRunning():
            self.brute_thread.terminate()
            self.brute_thread.wait()
            
        self.start_brute_btn.setEnabled(True)
        self.stop_brute_btn.setEnabled(False)
        self.results_text.append("Brute force stopped by user")
    
    def select_username_file(self):
        """Select username wordlist file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "Select Username Wordlist", 
            "", 
            "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.username_file_input.setText(file_path)
            self.add_file_to_list(file_path, "Username")
    
    def select_password_file(self):
        """Select password wordlist file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "Select Password Wordlist", 
            "", 
            "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.password_file_input.setText(file_path)
            self.add_file_to_list(file_path, "Password")
    
    def add_custom_files(self):
        """Add custom wordlist files"""
        file_paths, _ = QFileDialog.getOpenFileNames(
            self, 
            "Select Custom Wordlist Files", 
            "", 
            "Text Files (*.txt);;All Files (*)"
        )
        for file_path in file_paths:
            self.add_file_to_list(file_path, "Custom")
    
    def add_file_to_list(self, file_path, file_type):
        """Add file to the selected files list"""
        item = QListWidgetItem(f"[{file_type}] {file_path}")
        item.setData(Qt.UserRole, file_path)
        self.selected_files_list.addItem(item)
    
    def clear_custom_files(self):
        """Clear all selected files"""
        self.selected_files_list.clear()
        self.username_file_input.clear()
        self.password_file_input.clear()
    
    def get_selected_files(self):
        """Get list of selected files"""
        files = []
        for i in range(self.selected_files_list.count()):
            item = self.selected_files_list.item(i)
            if item:
                file_path = item.data(Qt.UserRole)
                files.append(file_path)
        return files
    
    def create_welcome_section(self, layout):
        """Create welcome section with comprehensive brute force guide"""
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
        
        welcome_layout = QVBoxLayout(welcome_widget)
        
        # Main welcome text
        welcome_text = QLabel("🚀 COMPREHENSIVE BRUTE FORCE ATTACKER - ALL FEATURES IN ONE CLICK")
        welcome_text.setStyleSheet("font-size: 16px; font-weight: bold; color: white;")
        welcome_layout.addWidget(welcome_text)
        
        # Features list
        features_text = QLabel("""
        <h3>🎯 Ultimate Brute Force Features:</h3>
        <ul>
        <li>✅ Multi-Service Attack (SSH, FTP, HTTP, MySQL, PostgreSQL, MSSQL, MongoDB, Redis)</li>
        <li>✅ Advanced Attack Techniques (Intelligent, Dictionary, Hybrid, Mask, Rule-based)</li>
        <li>✅ Comprehensive Results Display (Credentials, Statistics, Vulnerabilities)</li>
        <li>✅ Real-time Progress Monitoring</li>
        <li>✅ Security Analysis & Recommendations</li>
        <li>✅ Export Results to Multiple Formats</li>
        <li>✅ Full Page Scrolling Controls (⬆️⬇️ buttons + keyboard shortcuts)</li>
        </ul>
        <p><b>🚀 Quick Start:</b> Enter target → Click "START COMPREHENSIVE BRUTE FORCE" → View all results!</p>
        <p><b>📜 Scroll Controls:</b> Use ⬆️⬇️ buttons or keyboard shortcuts (Ctrl+Home/End, PgUp/PgDown)</p>
        """)
        features_text.setWordWrap(True)
        features_text.setStyleSheet("font-size: 11px; color: #ecf0f1;")
        welcome_layout.addWidget(features_text)
        
        layout.addWidget(welcome_widget)
    
    def setup_keyboard_shortcuts(self):
        """Set up keyboard shortcuts for page scrolling"""
        from PyQt5.QtWidgets import QShortcut
        from PyQt5.QtGui import QKeySequence
        
        # Ctrl+Home - Scroll to top
        scroll_top_shortcut = QShortcut(QKeySequence("Ctrl+Home"), self)
        scroll_top_shortcut.activated.connect(self.scroll_to_top)
        
        # Ctrl+End - Scroll to bottom
        scroll_bottom_shortcut = QShortcut(QKeySequence("Ctrl+End"), self)
        scroll_bottom_shortcut.activated.connect(self.scroll_to_bottom)
        
        # Page Down - Scroll down one page
        page_down_shortcut = QShortcut(QKeySequence("PgDown"), self)
        page_down_shortcut.activated.connect(self.scroll_page_down)
        
        # Page Up - Scroll up one page
        page_up_shortcut = QShortcut(QKeySequence("PgUp"), self)
        page_up_shortcut.activated.connect(self.scroll_page_up)
        
    def scroll_page_down(self):
        """Scroll down one page"""
        if hasattr(self, 'main_scroll'):
            scrollbar = self.main_scroll.verticalScrollBar()
            current_value = scrollbar.value()
            page_step = scrollbar.pageStep()
            scrollbar.setValue(current_value + page_step)
            self.results_text.append("📄 Scrolled down one page")
    
    def scroll_page_up(self):
        """Scroll up one page"""
        if hasattr(self, 'main_scroll'):
            scrollbar = self.main_scroll.verticalScrollBar()
            current_value = scrollbar.value()
            page_step = scrollbar.pageStep()
            scrollbar.setValue(max(0, current_value - page_step))
            self.results_text.append("📄 Scrolled up one page")

class BruteForceThread(QThread):
    """Thread for running brute force attacks"""
    result = pyqtSignal(dict)
    
    def __init__(self, target, options):
        super().__init__()
        self.target = target
        self.options = options
        
    def run(self):
        """Run the brute force attack"""
        try:
            try:
                from core.brute_forcer import BruteForcer
            except ImportError:
                self.result.emit({'error': 'BruteForcer module not available'})
                return
                
            brute_forcer = BruteForcer()
            
            # Prepare target data for brute forcer
            target_data = {
                'target': self.target,
                'port': self.options.get('port', 22),
                'service': self.options.get('service', 'ssh'),
                'usernames': [],
                'passwords': []
            }
            
            # Add custom usernames/passwords if provided
            if self.options.get('username'):
                target_data['usernames'] = [self.options['username']]
            if self.options.get('password'):
                target_data['passwords'] = [self.options['password']]
            
            # If use_wordlists is False, don't use built-in wordlists
            if not self.options.get('use_wordlists', True):
                # Only use custom usernames/passwords, not built-in wordlists
                if not target_data.get('usernames'):
                    target_data['usernames'] = []
                if not target_data.get('passwords'):
                    target_data['passwords'] = []
            
            # Run comprehensive brute force
            results = brute_forcer.comprehensive_brute_force([target_data])
            
            self.result.emit(results)
            
        except Exception as e:
            self.result.emit({'error': str(e)})

class ComprehensiveBruteForceThread(QThread):
    """Thread for running comprehensive brute force attacks with all features"""
    progress = pyqtSignal(str)
    result = pyqtSignal(dict)
    
    def __init__(self, target, options):
        super().__init__()
        self.target = target
        self.options = options
        
    def run(self):
        """Run the comprehensive brute force attack"""
        try:
            try:
                from core.brute_forcer import BruteForcer
            except ImportError:
                self.result.emit({'error': 'BruteForcer module not available'})
                return
            
            self.progress.emit("🚀 Initializing comprehensive brute force attack...")
            
            # Initialize brute forcer with comprehensive settings
            brute_forcer = BruteForcer(
                max_threads=self.options.get('threads', 20),
                delay=self.options.get('delay', 0.1),
                attack_mode=self.options.get('attack_mode', 'normal')
            )
            
            # Define all services to test
            services_to_test = [
                {'service': 'ssh', 'port': 22, 'name': 'SSH'},
                {'service': 'ftp', 'port': 21, 'name': 'FTP'},
                {'service': 'http', 'port': 80, 'name': 'HTTP'},
                {'service': 'mysql', 'port': 3306, 'name': 'MySQL'},
                {'service': 'postgresql', 'port': 5432, 'name': 'PostgreSQL'},
                {'service': 'mssql', 'port': 1433, 'name': 'MSSQL'},
                {'service': 'mongodb', 'port': 27017, 'name': 'MongoDB'},
                {'service': 'redis', 'port': 6379, 'name': 'Redis'}
            ]
            
            all_results = {
                'target': self.target,
                'found_credentials': [],
                'attack_stats': {
                    'total_attempts': 0,
                    'successful_attempts': 0,
                    'failed_attempts': 0,
                    'rate_limited': 0,
                    'connection_errors': 0
                },
                'vulnerabilities': [],
                'recommendations': []
            }
            
            # Test each service
            for service_info in services_to_test:
                service = service_info['service']
                port = service_info['port']
                name = service_info['name']
                
                self.progress.emit(f"🔍 Testing {name} service on port {port}...")
                
                # Prepare attack options for this service
                attack_options = {
                    'technique': self.options.get('technique', 'intelligent'),
                    'wordlist_category': self.options.get('wordlist_category', 'common'),
                    'attack_mode': self.options.get('attack_mode', 'normal'),
                    'max_attempts': min(self.options.get('max_attempts', 1000), 500),  # Limit per service
                    'delay': self.options.get('delay', 0.1),
                    'rate_limit_detection': self.options.get('rate_limit_detection', True),
                    'pattern_matching': self.options.get('pattern_matching', True)
                }
                
                try:
                    # Run advanced brute force for this service
                    service_results = brute_forcer.advanced_brute_force(
                        self.target, port, service, attack_options
                    )
                    
                    # Process results
                    if service_results.get('found_credentials'):
                        for cred in service_results['found_credentials']:
                            cred['service'] = name
                            all_results['found_credentials'].append(cred)
                            self.progress.emit(f"✅ Found {name} credentials: {cred.get('username', '')}:{cred.get('password', '')}")
                    
                    # Update statistics
                    stats = service_results.get('attack_stats', {})
                    all_results['attack_stats']['total_attempts'] += stats.get('total_attempts', 0)
                    all_results['attack_stats']['successful_attempts'] += stats.get('successful_attempts', 0)
                    all_results['attack_stats']['failed_attempts'] += stats.get('failed_attempts', 0)
                    all_results['attack_stats']['rate_limited'] += stats.get('rate_limited', 0)
                    all_results['attack_stats']['connection_errors'] += stats.get('connection_errors', 0)
                    
                    # Collect vulnerabilities
                    if service_results.get('vulnerabilities'):
                        all_results['vulnerabilities'].extend(service_results['vulnerabilities'])
                    
                    # Collect recommendations
                    if service_results.get('recommendations'):
                        all_results['recommendations'].extend(service_results['recommendations'])
                    
                except Exception as e:
                    self.progress.emit(f"⚠️ Error testing {name}: {str(e)}")
                    all_results['attack_stats']['connection_errors'] += 1
                    continue
            
            # Analyze comprehensive results
            self.progress.emit("📊 Analyzing comprehensive attack results...")
            
            # Add comprehensive vulnerabilities
            if all_results['found_credentials']:
                all_results['vulnerabilities'].append({
                    'type': 'Weak Authentication',
                    'severity': 'Critical',
                    'description': f"Found {len(all_results['found_credentials'])} valid credentials across multiple services",
                    'recommendation': 'Implement strong password policies and multi-factor authentication'
                })
            
            # Add comprehensive recommendations
            if all_results['found_credentials']:
                all_results['recommendations'].extend([
                    'Implement strong password policies across all services',
                    'Enable account lockout mechanisms',
                    'Use multi-factor authentication where possible',
                    'Regular security audits and penetration testing',
                    'Monitor for brute force attacks',
                    'Implement rate limiting on all authentication endpoints'
                ])
            
            self.progress.emit("🎉 Comprehensive brute force attack completed!")
            self.result.emit(all_results)
            
        except Exception as e:
            self.result.emit({'error': str(e)})

class AdvancedBruteForceThread(QThread):
    """Thread for running advanced brute force attacks"""
    result = pyqtSignal(dict)
    
    def __init__(self, target, options):
        super().__init__()
        self.target = target
        self.options = options
        
    def run(self):
        """Run the advanced brute force attack"""
        try:
            try:
                from core.brute_forcer import BruteForcer
            except ImportError:
                self.result.emit({'error': 'BruteForcer module not available'})
                return
                
            brute_forcer = BruteForcer(
                max_threads=self.options.get('threads', 10),
                delay=self.options.get('delay', 1.0),
                attack_mode=self.options.get('attack_mode', 'normal')
            )
            
            # Prepare attack options
            attack_options = {
                'technique': self.options.get('technique', 'intelligent'),
                'wordlist_category': self.options.get('wordlist_category', 'common'),
                'attack_mode': self.options.get('attack_mode', 'normal'),
                'max_attempts': self.options.get('max_attempts', 1000),
                'delay': self.options.get('delay', 1.0),
                'rate_limit_detection': self.options.get('rate_limit_detection', True),
                'pattern_matching': self.options.get('pattern_matching', True)
            }
            
            # Run advanced brute force
            results = brute_forcer.advanced_brute_force(
                self.target,
                self.options.get('port', 22),
                self.options.get('service', 'ssh'),
                attack_options
            )
            
            self.result.emit(results)
            
        except Exception as e:
            self.result.emit({'error': str(e)})

class ComprehensiveBruteForceThread(QThread):
    """Thread for running comprehensive brute force attacks with all features"""
    progress = pyqtSignal(str)
    result = pyqtSignal(dict)
    
    def __init__(self, target, options):
        super().__init__()
        self.target = target
        self.options = options
        
    def run(self):
        """Run the comprehensive brute force attack"""
        try:
            try:
                from core.brute_forcer import BruteForcer
            except ImportError:
                self.result.emit({'error': 'BruteForcer module not available'})
                return
            
            self.progress.emit("🚀 Initializing comprehensive brute force attack...")
            
            # Initialize brute forcer with comprehensive settings
            brute_forcer = BruteForcer(
                max_threads=self.options.get('threads', 20),
                delay=self.options.get('delay', 0.1),
                attack_mode=self.options.get('attack_mode', 'normal')
            )
            
            # Define all services to test
            services_to_test = [
                {'service': 'ssh', 'port': 22, 'name': 'SSH'},
                {'service': 'ftp', 'port': 21, 'name': 'FTP'},
                {'service': 'http', 'port': 80, 'name': 'HTTP'},
                {'service': 'mysql', 'port': 3306, 'name': 'MySQL'},
                {'service': 'postgresql', 'port': 5432, 'name': 'PostgreSQL'},
                {'service': 'mssql', 'port': 1433, 'name': 'MSSQL'},
                {'service': 'mongodb', 'port': 27017, 'name': 'MongoDB'},
                {'service': 'redis', 'port': 6379, 'name': 'Redis'}
            ]
            
            all_results = {
                'target': self.target,
                'found_credentials': [],
                'attack_stats': {
                    'total_attempts': 0,
                    'successful_attempts': 0,
                    'failed_attempts': 0,
                    'rate_limited': 0,
                    'connection_errors': 0
                },
                'vulnerabilities': [],
                'recommendations': []
            }
            
            # Test each service
            for service_info in services_to_test:
                service = service_info['service']
                port = service_info['port']
                name = service_info['name']
                
                self.progress.emit(f"🔍 Testing {name} service on port {port}...")
                
                # Prepare attack options for this service
                attack_options = {
                    'technique': self.options.get('technique', 'intelligent'),
                    'wordlist_category': self.options.get('wordlist_category', 'common'),
                    'attack_mode': self.options.get('attack_mode', 'normal'),
                    'max_attempts': min(self.options.get('max_attempts', 1000), 500),  # Limit per service
                    'delay': self.options.get('delay', 0.1),
                    'rate_limit_detection': self.options.get('rate_limit_detection', True),
                    'pattern_matching': self.options.get('pattern_matching', True)
                }
                
                try:
                    # Run advanced brute force for this service
                    service_results = brute_forcer.advanced_brute_force(
                        self.target, port, service, attack_options
                    )
                    
                    # Process results
                    if service_results.get('found_credentials'):
                        for cred in service_results['found_credentials']:
                            cred['service'] = name
                            all_results['found_credentials'].append(cred)
                            self.progress.emit(f"✅ Found {name} credentials: {cred.get('username', '')}:{cred.get('password', '')}")
                    
                    # Update statistics
                    stats = service_results.get('attack_stats', {})
                    all_results['attack_stats']['total_attempts'] += stats.get('total_attempts', 0)
                    all_results['attack_stats']['successful_attempts'] += stats.get('successful_attempts', 0)
                    all_results['attack_stats']['failed_attempts'] += stats.get('failed_attempts', 0)
                    all_results['attack_stats']['rate_limited'] += stats.get('rate_limited', 0)
                    all_results['attack_stats']['connection_errors'] += stats.get('connection_errors', 0)
                    
                    # Collect vulnerabilities
                    if service_results.get('vulnerabilities'):
                        all_results['vulnerabilities'].extend(service_results['vulnerabilities'])
                    
                    # Collect recommendations
                    if service_results.get('recommendations'):
                        all_results['recommendations'].extend(service_results['recommendations'])
                    
                except Exception as e:
                    self.progress.emit(f"⚠️ Error testing {name}: {str(e)}")
                    all_results['attack_stats']['connection_errors'] += 1
                    continue
            
            # Analyze comprehensive results
            self.progress.emit("📊 Analyzing comprehensive attack results...")
            
            # Add comprehensive vulnerabilities
            if all_results['found_credentials']:
                all_results['vulnerabilities'].append({
                    'type': 'Weak Authentication',
                    'severity': 'Critical',
                    'description': f"Found {len(all_results['found_credentials'])} valid credentials across multiple services",
                    'recommendation': 'Implement strong password policies and multi-factor authentication'
                })
            
            # Add comprehensive recommendations
            if all_results['found_credentials']:
                all_results['recommendations'].extend([
                    'Implement strong password policies across all services',
                    'Enable account lockout mechanisms',
                    'Use multi-factor authentication where possible',
                    'Regular security audits and penetration testing',
                    'Monitor for brute force attacks',
                    'Implement rate limiting on all authentication endpoints'
                ])
            
            self.progress.emit("🎉 Comprehensive brute force attack completed!")
            self.result.emit(all_results)
            
        except Exception as e:
            self.result.emit({'error': str(e)})
