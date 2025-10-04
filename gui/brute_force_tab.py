#!/usr/bin/env python3
"""
Brute Force Tab
GUI for brute force testing functionality
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QLineEdit, QPushButton, QTextEdit,
                             QCheckBox, QGroupBox, QTableWidget, QTableWidgetItem,
                             QHeaderView, QSpinBox, QComboBox, QScrollArea,
                             QFileDialog, QListWidget, QListWidgetItem)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

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
        
        self.start_brute_btn = QPushButton("Start Brute Force")
        self.start_brute_btn.clicked.connect(self.start_brute_force)
        button_layout.addWidget(self.start_brute_btn)
        
        self.advanced_brute_btn = QPushButton("Advanced Brute Force")
        self.advanced_brute_btn.clicked.connect(self.start_advanced_brute_force)
        button_layout.addWidget(self.advanced_brute_btn)
        
        self.stop_brute_btn = QPushButton("Stop Brute Force")
        self.stop_brute_btn.setEnabled(False)
        self.stop_brute_btn.clicked.connect(self.stop_brute_force)
        button_layout.addWidget(self.stop_brute_btn)
        
        layout.addLayout(button_layout)
        
        # Results section
        results_group = QGroupBox("Brute Force Results")
        results_layout = QVBoxLayout(results_group)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Username", "Password", "Status", "Response"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        results_layout.addWidget(self.results_table)
        
        # Results text
        self.results_text = QTextEdit()
        self.results_text.setMaximumHeight(200)
        self.results_text.setPlaceholderText("Brute force results will appear here...")
        results_layout.addWidget(self.results_text)
        
        layout.addWidget(results_group)
        
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
