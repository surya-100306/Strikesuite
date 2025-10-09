#!/usr/bin/env python3
"""
StrikeSuite Main Window
Main GUI application window
"""

import sys
import os
from pathlib import Path
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, 
                             QVBoxLayout, QHBoxLayout, QWidget, QLabel,
                             QPushButton, QTextEdit, QStatusBar, QMenuBar,
                             QAction, QMessageBox, QFileDialog, QScrollArea,
                             QProgressBar, QSplitter, QDockWidget, QToolBar,
                             QLineEdit, QScrollBar, QFrame)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSettings
from PyQt5.QtGui import QIcon, QFont, QPalette, QColor, QKeySequence

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Import core modules with error handling
try:
    from core.scanner import NetworkScanner
except ImportError:
    NetworkScanner = None

try:
    from core.api_tester import APITester
except ImportError:
    APITester = None

try:
    from core.vulnerability_scanner import VulnerabilityScanner
except ImportError:
    VulnerabilityScanner = None

try:
    from core.exploit_module import ExploitModule
except ImportError:
    ExploitModule = None

try:
    from core.brute_forcer import BruteForcer
except ImportError:
    BruteForcer = None

try:
    from core.post_exploitation import PostExploitation
except ImportError:
    PostExploitation = None

try:
    from core.reporter import ReportGenerator
except ImportError:
    ReportGenerator = None

try:
    from utils.db_utils import init_db
except ImportError:
    init_db = None

class ScanWorker(QThread):
    """Worker thread for running scans"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    
    def __init__(self, scan_type, target, **kwargs):
        super().__init__()
        self.scan_type = scan_type
        self.target = target
        self.kwargs = kwargs
    
    def run(self):
        """Run the scan in background thread"""
        try:
            if self.scan_type == "port_scan":
                if NetworkScanner is None:
                    self.progress.emit("NetworkScanner module not available")
                    return
                scanner = NetworkScanner()
                results = scanner.scan_ports(self.target, self.kwargs.get('ports', [22, 80, 443]))
                self.finished.emit(results)
            elif self.scan_type == "vuln_scan":
                if VulnerabilityScanner is None:
                    self.progress.emit("VulnerabilityScanner module not available")
                    return
                scanner = VulnerabilityScanner()
                targets = [{'hostname': self.target, 'port': 80, 'service': 'http'}]
                results = scanner.comprehensive_scan(targets)
                self.finished.emit(results)
            elif self.scan_type == "api_test":
                if APITester is None:
                    self.progress.emit("APITester module not available")
                    return
                tester = APITester(self.target)
                endpoints = [f"{self.target}/api/users", f"{self.target}/api/admin"]
                results = tester.comprehensive_test(endpoints)
                self.finished.emit(results)
        except Exception as e:
            self.progress.emit(f"Error: {e}")

class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self, plugin_manager=None):
        super().__init__()
        self.plugin_manager = plugin_manager
        self.scan_worker = None
        self.is_fullscreen = False
        self.original_geometry = None
        self.init_ui()
        self.setup_database()
        
    def init_ui(self):
        """Initialize the user interface with modern, user-friendly design"""
        self.setWindowTitle("🚀 StrikeSuite v1.0 - Advanced Penetration Testing Toolkit")
        self.setGeometry(50, 50, 1600, 1000)
        
        # Modern dark theme with professional styling
        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #2c3e50, stop:1 #34495e);
                color: #ecf0f1;
            }
            
            QTabWidget::pane {
                border: 2px solid #3498db;
                border-radius: 8px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #ffffff, stop:1 #f8f9fa);
                margin-top: 2px;
            }
            
            QTabWidget::tab-bar {
                alignment: left;
            }
            
            QTabBar::tab {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #95a5a6, stop:1 #7f8c8d);
                color: white;
                padding: 12px 20px;
                margin-right: 3px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                font-weight: bold;
                font-size: 12px;
                min-width: 120px;
            }
            
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #3498db, stop:1 #2980b9);
                color: white;
            }
            
            QTabBar::tab:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #3498db, stop:1 #2980b9);
            }
            
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #27ae60, stop:1 #229954);
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 11px;
                min-height: 20px;
            }
            
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #2ecc71, stop:1 #27ae60);
            }
            
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #229954, stop:1 #1e8449);
            }
            
            QPushButton:disabled {
                background: #bdc3c7;
                color: #7f8c8d;
            }
            
            QLineEdit, QTextEdit, QPlainTextEdit {
                background: white;
                border: 2px solid #bdc3c7;
                border-radius: 6px;
                padding: 8px;
                font-size: 11px;
                color: #2c3e50;
            }
            
            QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
                border-color: #3498db;
            }
            
            QLabel {
                color: #2c3e50;
                font-weight: bold;
                font-size: 11px;
            }
            
            QGroupBox {
                font-weight: bold;
                border: 2px solid #bdc3c7;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background: #f8f9fa;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #2c3e50;
            }
            
            QProgressBar {
                border: 2px solid #bdc3c7;
                border-radius: 6px;
                text-align: center;
                background: #ecf0f1;
            }
            
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #3498db, stop:1 #2980b9);
                border-radius: 4px;
            }
            
            QStatusBar {
                background: #34495e;
                color: #ecf0f1;
                border-top: 2px solid #3498db;
                font-weight: bold;
            }
            
            QMenuBar {
                background: #2c3e50;
                color: #ecf0f1;
                border-bottom: 2px solid #3498db;
            }
            
            QMenuBar::item {
                background: transparent;
                padding: 8px 12px;
            }
            
            QMenuBar::item:selected {
                background: #3498db;
            }
            
            QMenu {
                background: white;
                border: 2px solid #bdc3c7;
                border-radius: 6px;
            }
            
            QMenu::item {
                padding: 8px 20px;
                color: #2c3e50;
            }
            
            QMenu::item:selected {
                background: #3498db;
                color: white;
            }
        """)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create toolbar
        self.create_toolbar()
        
        # Create central widget with modern layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout with header and content
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        # Create header with welcome message
        self.create_header(main_layout)
        
        # Create tab widget with enhanced styling
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabPosition(QTabWidget.North)
        self.tab_widget.setMovable(True)
        self.tab_widget.setTabsClosable(False)
        main_layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.create_network_tab()
        self.create_api_tab()
        self.create_vulnerability_tab()
        self.create_exploitation_tab()
        self.create_brute_force_tab()
        self.create_post_exploit_tab()
        self.create_reporting_tab()
        self.create_plugins_tab()
        self.create_cve_training_tab()
        
        # Create status bar with enhanced information
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("🚀 StrikeSuite Ready - Select a target and start scanning")
        
        # Add permanent widgets to status bar
        self.scan_status_label = QLabel("Status: Ready")
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumWidth(200)
        
        self.status_bar.addPermanentWidget(self.scan_status_label)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
    def create_menu_bar(self):
        """Create modern menu bar with helpful options"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('📁 File')
        
        new_action = QAction('🆕 New Scan', self)
        new_action.setShortcut('Ctrl+N')
        new_action.setStatusTip('Start a new security scan')
        new_action.triggered.connect(self.new_scan)
        file_menu.addAction(new_action)
        
        open_action = QAction('📂 Open Results', self)
        open_action.setShortcut('Ctrl+O')
        open_action.setStatusTip('Open saved scan results')
        open_action.triggered.connect(self.open_results)
        file_menu.addAction(open_action)
        
        save_action = QAction('💾 Save Results', self)
        save_action.setShortcut('Ctrl+S')
        save_action.setStatusTip('Save current scan results')
        save_action.triggered.connect(self.save_results)
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('🚪 Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.setStatusTip('Exit StrikeSuite')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Edit menu
        edit_menu = menubar.addMenu('✏️ Edit')
        
        # Copy action
        copy_action = QAction('📋 Copy', self)
        copy_action.setShortcut(QKeySequence.Copy)
        copy_action.setStatusTip('Copy selected text')
        copy_action.triggered.connect(self.copy_selection)
        edit_menu.addAction(copy_action)
        
        # Paste action
        paste_action = QAction('📄 Paste', self)
        paste_action.setShortcut(QKeySequence.Paste)
        paste_action.setStatusTip('Paste from clipboard')
        paste_action.triggered.connect(self.paste_content)
        edit_menu.addAction(paste_action)
        
        # Select All action
        select_all_action = QAction('🔍 Select All', self)
        select_all_action.setShortcut(QKeySequence.SelectAll)
        select_all_action.setStatusTip('Select all text')
        select_all_action.triggered.connect(self.select_all_content)
        edit_menu.addAction(select_all_action)
        
        edit_menu.addSeparator()
        
        # Clear action
        clear_action = QAction('🗑️ Clear', self)
        clear_action.setShortcut('Ctrl+Delete')
        clear_action.setStatusTip('Clear current content')
        clear_action.triggered.connect(self.clear_content)
        edit_menu.addAction(clear_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('🔧 Tools')
        
        quick_scan_action = QAction('⚡ Quick Scan', self)
        quick_scan_action.setStatusTip('Run a quick port scan')
        quick_scan_action.triggered.connect(self.quick_scan)
        tools_menu.addAction(quick_scan_action)
        
        full_scan_action = QAction('🔍 Full Assessment', self)
        full_scan_action.setStatusTip('Run comprehensive security assessment')
        full_scan_action.triggered.connect(self.full_assessment)
        tools_menu.addAction(full_scan_action)
        
        tools_menu.addSeparator()
        
        # Full screen toggle
        self.fullscreen_action = QAction('🖥️ Toggle Full Screen', self)
        self.fullscreen_action.setShortcut('F11')
        self.fullscreen_action.setStatusTip('Toggle full screen mode')
        self.fullscreen_action.triggered.connect(self.toggle_fullscreen)
        tools_menu.addAction(self.fullscreen_action)
        
        # Scroll controls
        scroll_down_action = QAction('⬇️ Scroll Down', self)
        scroll_down_action.setShortcut('Ctrl+Down')
        scroll_down_action.setStatusTip('Scroll down in current tab')
        scroll_down_action.triggered.connect(self.scroll_down)
        tools_menu.addAction(scroll_down_action)
        
        scroll_up_action = QAction('⬆️ Scroll Up', self)
        scroll_up_action.setShortcut('Ctrl+Up')
        scroll_up_action.setStatusTip('Scroll up in current tab')
        scroll_up_action.triggered.connect(self.scroll_up)
        tools_menu.addAction(scroll_up_action)
        
        tools_menu.addSeparator()
        
        settings_action = QAction('⚙️ Settings', self)
        settings_action.setStatusTip('Configure StrikeSuite settings')
        settings_action.triggered.connect(self.show_settings)
        tools_menu.addAction(settings_action)
        
        # Help menu
        help_menu = menubar.addMenu('❓ Help')
        
        user_guide_action = QAction('📚 User Guide', self)
        user_guide_action.setStatusTip('Open user guide')
        user_guide_action.triggered.connect(self.show_user_guide)
        help_menu.addAction(user_guide_action)
        
        about_action = QAction('ℹ️ About', self)
        about_action.setStatusTip('About StrikeSuite')
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_toolbar(self):
        """Create empty toolbar - buttons removed as requested"""
        # Toolbar removed - no buttons needed
        pass
    
    def create_header(self, layout):
        """Create welcome header with target input"""
        header_widget = QWidget()
        header_widget.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #3498db, stop:1 #2980b9);
                border-radius: 10px;
                padding: 15px;
            }
            QLabel {
                color: white;
                font-size: 14px;
                font-weight: bold;
            }
            QLineEdit {
                background: white;
                border: 2px solid #ecf0f1;
                border-radius: 6px;
                padding: 8px;
                font-size: 12px;
            }
        """)
        
        header_layout = QHBoxLayout(header_widget)
        
        # Welcome message
        welcome_label = QLabel("🎯 Welcome to StrikeSuite - Advanced Penetration Testing Toolkit")
        welcome_label.setStyleSheet("font-size: 16px; font-weight: bold; color: white;")
        header_layout.addWidget(welcome_label)
        
        header_layout.addStretch()
        
        # Target input
        target_label = QLabel("Target:")
        target_label.setStyleSheet("color: white; font-weight: bold;")
        header_layout.addWidget(target_label)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter target IP or hostname (e.g., 192.168.1.1)")
        self.target_input.setMinimumWidth(300)
        self.target_input.returnPressed.connect(self.quick_scan)
        header_layout.addWidget(self.target_input)
        
        # Quick scan button
        quick_btn = QPushButton("🚀 Quick Scan")
        quick_btn.setStyleSheet("""
            QPushButton {
                background: #27ae60;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #2ecc71;
            }
        """)
        quick_btn.clicked.connect(self.quick_scan)
        header_layout.addWidget(quick_btn)
        
        layout.addWidget(header_widget)
    
    def create_network_tab(self):
        """Create network scanning tab"""
        from .network_tab import NetworkTab
        self.network_tab = NetworkTab()
        self.tab_widget.addTab(self.network_tab, "Network Scanner")
        
    def create_api_tab(self):
        """Create API testing tab"""
        from .api_tab import APITab
        self.api_tab = APITab()
        self.tab_widget.addTab(self.api_tab, "API Security")
        
    def create_vulnerability_tab(self):
        """Create vulnerability assessment tab"""
        from .vulnerability_tab import VulnerabilityTab
        self.vulnerability_tab = VulnerabilityTab()
        self.tab_widget.addTab(self.vulnerability_tab, "Vulnerability Scanner")
        
    def create_exploitation_tab(self):
        """Create exploitation tab"""
        from .exploitation_tab import ExploitationTab
        self.exploitation_tab = ExploitationTab()
        self.tab_widget.addTab(self.exploitation_tab, "Exploitation")
        
    def create_brute_force_tab(self):
        """Create brute force tab"""
        from .brute_force_tab import BruteForceTab
        self.brute_force_tab = BruteForceTab()
        self.tab_widget.addTab(self.brute_force_tab, "Brute Force")
        
    def create_post_exploit_tab(self):
        """Create post-exploitation tab"""
        from .post_exploit_tab import PostExploitTab
        self.post_exploit_tab = PostExploitTab()
        self.tab_widget.addTab(self.post_exploit_tab, "Post-Exploitation")
        
    def create_reporting_tab(self):
        """Create reporting tab"""
        from .reporting_tab import ReportingTab
        self.reporting_tab = ReportingTab()
        self.tab_widget.addTab(self.reporting_tab, "Reporting")
        
    def create_plugins_tab(self):
        """Create plugins tab"""
        from .plugins_tab import PluginsTab
        self.plugins_tab = PluginsTab(self.plugin_manager)
        self.tab_widget.addTab(self.plugins_tab, "Plugins")
        
    def create_cve_training_tab(self):
        """Create CVE training tab"""
        from .cve_training_tab import CVETrainingTab
        self.cve_training_tab = CVETrainingTab()
        self.tab_widget.addTab(self.cve_training_tab, "🎓 CVE Training")
        
    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        new_action = QAction('New Scan', self)
        new_action.setShortcut('Ctrl+N')
        new_action.triggered.connect(self.new_scan)
        file_menu.addAction(new_action)
        
        save_action = QAction('Save Results', self)
        save_action.setShortcut('Ctrl+S')
        save_action.triggered.connect(self.save_results)
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        
        db_action = QAction('Database Manager', self)
        db_action.triggered.connect(self.open_database_manager)
        tools_menu.addAction(db_action)
        
        settings_action = QAction('Settings', self)
        settings_action.triggered.connect(self.open_settings)
        tools_menu.addAction(settings_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def setup_database(self):
        """Initialize database"""
        try:
            if init_db is not None:
                init_db()
                self.status_bar.showMessage("Database initialized")
            else:
                self.status_bar.showMessage("Database module not available")
        except Exception as e:
            QMessageBox.warning(self, "Database Error", f"Failed to initialize database: {e}")
    
    def new_scan(self):
        """Start new scan"""
        self.status_bar.showMessage("Starting new scan...")
        
    def save_results(self):
        """Save scan results"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Results", "", "JSON Files (*.json);;All Files (*)"
        )
        if filename:
            self.status_bar.showMessage(f"Results saved to {filename}")
    
    def open_database_manager(self):
        """Open database manager"""
        QMessageBox.information(self, "Database Manager", "Database manager not implemented yet")
    
    def open_settings(self):
        """Open settings dialog"""
        QMessageBox.information(self, "Settings", "Settings dialog not implemented yet")
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, "About StrikeSuite", 
                         "StrikeSuite v1.0\n"
                         "Advanced Penetration Testing Toolkit\n\n"
                         "A comprehensive security testing platform\n"
                         "for ethical hacking and vulnerability assessment.")
    
    def closeEvent(self, event):
        """Handle application close"""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.terminate()
            self.scan_worker.wait()
        event.accept()
    
    # Menu and toolbar action methods
    def new_scan(self):
        """Start a new scan"""
        self.target_input.clear()
        self.scan_status_label.setText("Status: Ready for new scan")
        self.status_bar.showMessage("🚀 Ready for new scan - Enter target and select scan type")
    
    def open_results(self):
        """Open saved scan results"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Scan Results", "", 
            "JSON Files (*.json);;All Files (*)"
        )
        if file_path:
            self.status_bar.showMessage(f"📂 Opened results from {file_path}")
            # TODO: Implement results loading
    
    def save_results(self):
        """Save current scan results"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Scan Results", "scan_results.json",
            "JSON Files (*.json);;All Files (*)"
        )
        if file_path:
            self.status_bar.showMessage(f"💾 Saved results to {file_path}")
            # TODO: Implement results saving
    
    def quick_scan(self):
        """Run a quick port scan"""
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "No Target", "Please enter a target IP or hostname")
            return
        
        self.status_bar.showMessage(f"⚡ Starting quick scan on {target}")
        self.scan_status_label.setText("Status: Quick scan running...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        # Switch to network tab
        self.tab_widget.setCurrentIndex(0)
        
        # TODO: Implement actual quick scan
        QMessageBox.information(self, "Quick Scan", f"Quick scan started on {target}")
    
    def full_assessment(self):
        """Run comprehensive security assessment automatically"""
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "No Target", "Please enter a target IP or hostname")
            return
        
        # Start comprehensive assessment automatically
        self.status_bar.showMessage(f"🚀 Starting automatic full assessment on {target}")
        self.scan_status_label.setText("Status: Full assessment running...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        # Show what will be tested
        self.status_bar.showMessage(f"🔍 Running comprehensive security assessment on {target}")
        
        # Start comprehensive assessment automatically
        self.start_comprehensive_assessment(target)
    
    def start_comprehensive_assessment(self, target):
        """Start comprehensive security assessment with all scan types automatically"""
        try:
            # Import required modules
            from core.scanner import NetworkScanner
            from core.api_tester import APITester
            from core.vulnerability_scanner import VulnerabilityScanner
            from core.brute_forcer import BruteForcer
            from core.exploit_module import ExploitModule
            from core.post_exploitation import PostExploitation
            
            # Initialize scanners
            network_scanner = NetworkScanner()
            api_tester = APITester()
            vuln_scanner = VulnerabilityScanner()
            brute_forcer = BruteForcer()
            exploit_module = ExploitModule()
            post_exploit = PostExploitation()
            
            # Define assessment steps with progress tracking
            assessment_steps = [
                ("🔍 Network Port Scanning", lambda: network_scanner.advanced_port_scan(target, {
                    'scan_type': 'tcp_connect',
                    'ports': [22, 80, 443, 8080, 3389, 21, 23, 25, 53, 110, 143, 993, 995],
                    'os_detection': True,
                    'service_detection': True
                })),
                ("🛡️ Vulnerability Assessment", lambda: vuln_scanner.advanced_vulnerability_scan(target, {
                    'scan_depth': 'comprehensive',
                    'cve_check': True,
                    'risk_assessment': True
                })),
                ("🌐 API Security Testing", lambda: api_tester.advanced_api_test(target, {
                    'owasp_top10': True,
                    'injection_testing': True,
                    'authentication_testing': True
                })),
                ("🔐 Brute Force Testing", lambda: brute_forcer.advanced_brute_force(target, 22, 'ssh', {
                    'technique': 'intelligent',
                    'wordlist_category': 'common',
                    'max_attempts': 50
                })),
                ("💥 Exploitation Testing", lambda: exploit_module.advanced_exploitation_test(target, {
                    'payload_generation': True,
                    'evasion_techniques': True,
                    'exploit_chaining': True
                })),
                ("🔍 Post-Exploitation Analysis", lambda: post_exploit.advanced_post_exploitation(target, {
                    'system_enumeration': True,
                    'privilege_escalation': True,
                    'persistence_analysis': True
                }))
            ]
            
            # Run all assessment steps automatically
            completed_steps = 0
            total_steps = len(assessment_steps)
            
            failed_steps = []
            successful_steps = []
            
            for step_name, step_function in assessment_steps:
                self.status_bar.showMessage(f"Running {step_name}... ({completed_steps + 1}/{total_steps})")
                self.scan_status_label.setText(f"Status: {step_name}")
                
                try:
                    # Execute the scan step
                    result = step_function()
                    completed_steps += 1
                    successful_steps.append(step_name)
                    self.status_bar.showMessage(f"✅ {step_name} completed ({completed_steps}/{total_steps})")
                    
                except Exception as step_error:
                    completed_steps += 1
                    failed_steps.append(step_name)
                    self.status_bar.showMessage(f"⚠️ {step_name} failed: {str(step_error)} - Continuing with next scan...")
                    
                    # Continue with next step instead of stopping
                    continue
            
            # Complete assessment
            self.status_bar.showMessage(f"🎉 Comprehensive assessment completed for {target}")
            self.scan_status_label.setText("Status: Assessment completed")
            self.progress_bar.setVisible(False)
            
            # Automatically generate comprehensive report
            self.status_bar.showMessage("📊 Generating comprehensive security report...")
            self.scan_status_label.setText("Status: Generating report...")
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)  # Indeterminate progress
            
            # Generate automatic report with success/failure details
            report_path = self.generate_automatic_report(target, completed_steps, total_steps, successful_steps, failed_steps)
            
            # Show completion summary with success/failure details
            success_text = "\n".join([f"✅ {step}" for step in successful_steps])
            failure_text = "\n".join([f"⚠️ {step} (Failed)" for step in failed_steps]) if failed_steps else "None"
            
            QMessageBox.information(self, "Assessment Complete", 
                                 f"🎉 Automatic Full Assessment Completed!\n\n"
                                 f"Target: {target}\n"
                                 f"Steps Completed: {completed_steps}/{total_steps}\n"
                                 f"Successful: {len(successful_steps)}\n"
                                 f"Failed: {len(failed_steps)}\n\n"
                                 f"✅ Successful Scans:\n{success_text}\n\n"
                                 f"⚠️ Failed Scans:\n{failure_text}\n\n"
                                 f"📊 Comprehensive Report Generated:\n"
                                 f"{report_path}\n\n"
                                 f"Check individual tabs for detailed results.")
            
            self.status_bar.showMessage(f"✅ Assessment and report completed for {target}")
            self.scan_status_label.setText("Status: Assessment and report completed")
            self.progress_bar.setVisible(False)
            
        except Exception as e:
            self.status_bar.showMessage(f"❌ Assessment failed: {str(e)}")
            self.scan_status_label.setText("Status: Assessment failed")
            self.progress_bar.setVisible(False)
            QMessageBox.critical(self, "Assessment Error", f"Full assessment failed: {str(e)}")
    
    def generate_automatic_report(self, target, completed_steps, total_steps, successful_steps=None, failed_steps=None):
        """Generate comprehensive security report automatically"""
        try:
            import os
            import datetime
            from pathlib import Path
            
            # Create reports directory if it doesn't exist
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)
            
            # Generate timestamp for unique filename
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"strikesuite_full_assessment_{target.replace('.', '_').replace(':', '_')}_{timestamp}.html"
            report_path = reports_dir / report_filename
            
            # Generate comprehensive HTML report
            html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StrikeSuite Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
        .section {{ background: white; margin: 15px 0; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .success {{ color: #27ae60; font-weight: bold; }}
        .warning {{ color: #f39c12; font-weight: bold; }}
        .error {{ color: #e74c3c; font-weight: bold; }}
        .info {{ color: #3498db; font-weight: bold; }}
        h1 {{ margin: 0; font-size: 28px; }}
        h2 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 5px; }}
        .summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 10px 0; }}
        .footer {{ text-align: center; margin-top: 30px; color: #7f8c8d; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 StrikeSuite Security Assessment Report</h1>
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Assessment Date:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>Assessment Type:</strong> Comprehensive Full Assessment</p>
    </div>

    <div class="section">
        <h2>📊 Executive Summary</h2>
        <div class="summary">
            <p><span class="success">✅ Assessment Status:</span> Completed</p>
            <p><span class="info">📈 Steps Completed:</span> {completed_steps}/{total_steps}</p>
            <p><span class="info">🎯 Target:</span> {target}</p>
            <p><span class="info">⏱️ Assessment Duration:</span> Automated Full Assessment</p>
            <p><span class="success">✅ Successful Scans:</span> {len(successful_steps) if successful_steps else 0}</p>
            <p><span class="warning">⚠️ Failed Scans:</span> {len(failed_steps) if failed_steps else 0}</p>
        </div>
    </div>

    <div class="section">
        <h2>🔍 Assessment Modules Executed</h2>
        <ul>
            {self._generate_module_status_html(successful_steps, failed_steps)}
        </ul>
    </div>

    <div class="section">
        <h2>🛡️ Security Findings Summary</h2>
        <div class="summary">
            <p><span class="info">📋 Detailed findings are available in individual StrikeSuite tabs:</span></p>
            <ul>
                <li><strong>Network Tab:</strong> Port scan results and service detection</li>
                <li><strong>Vulnerability Tab:</strong> Security vulnerabilities and CVE information</li>
                <li><strong>API Tab:</strong> API security test results and OWASP findings</li>
                <li><strong>Brute Force Tab:</strong> Password security assessment results</li>
                <li><strong>Exploitation Tab:</strong> Exploit testing and payload generation results</li>
                <li><strong>Post-Exploit Tab:</strong> System analysis and enumeration results</li>
                <li><strong>Reporting Tab:</strong> Detailed report generation and export options</li>
            </ul>
        </div>
    </div>

    <div class="section">
        <h2>📈 Recommendations</h2>
        <div class="summary">
            <p><span class="warning">⚠️ General Security Recommendations:</span></p>
            <ul>
                <li>Review all identified vulnerabilities and prioritize remediation</li>
                <li>Implement proper access controls and authentication mechanisms</li>
                <li>Regular security assessments and penetration testing</li>
                <li>Keep systems and software updated with latest security patches</li>
                <li>Implement monitoring and logging for security events</li>
                <li>Conduct regular security awareness training</li>
            </ul>
        </div>
    </div>

    <div class="section">
        <h2>🔧 Technical Details</h2>
        <div class="summary">
            <p><strong>Assessment Tool:</strong> StrikeSuite v1.0 - Advanced Penetration Testing Toolkit</p>
            <p><strong>Assessment Method:</strong> Automated Comprehensive Security Assessment</p>
            <p><strong>Report Generated:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p><strong>Report Format:</strong> HTML (HyperText Markup Language)</p>
            <p><strong>Report Location:</strong> {report_path}</p>
        </div>
    </div>

    <div class="footer">
        <p><strong>🚀 StrikeSuite v1.0 - Advanced Penetration Testing Toolkit</strong></p>
        <p>Generated automatically on {datetime.datetime.now().strftime("%Y-%m-%d at %H:%M:%S")}</p>
        <p><em>⚠️ This report is for authorized security testing only. Use responsibly and ethically.</em></p>
    </div>
</body>
</html>
            """
            
            # Write the report to file
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.status_bar.showMessage(f"📊 Report generated: {report_path}")
            return str(report_path)
            
        except Exception as e:
            self.status_bar.showMessage(f"⚠️ Report generation failed: {str(e)}")
            return f"Report generation failed: {str(e)}"
    
    def _generate_module_status_html(self, successful_steps, failed_steps):
        """Generate HTML for module status in report"""
        all_modules = [
            ("🔍 Network Port Scanning", "Comprehensive port and service detection"),
            ("🛡️ Vulnerability Assessment", "CVE correlation and risk analysis"),
            ("🌐 API Security Testing", "OWASP API Top 10 testing"),
            ("🔐 Brute Force Testing", "Password and credential security testing"),
            ("💥 Exploitation Testing", "Exploit effectiveness and payload generation"),
            ("🔍 Post-Exploitation Analysis", "System enumeration and privilege escalation")
        ]
        
        html_items = []
        for module_name, description in all_modules:
            if successful_steps and any(module_name in step for step in successful_steps):
                html_items.append(f'<li><span class="success">✅ {module_name}</span> - {description}</li>')
            elif failed_steps and any(module_name in step for step in failed_steps):
                html_items.append(f'<li><span class="error">❌ {module_name}</span> - {description} (Failed)</li>')
            else:
                html_items.append(f'<li><span class="info">ℹ️ {module_name}</span> - {description}</li>')
        
        return "\n".join(html_items)
    
    def run_assessment_step(self, step_name, scan_function):
        """Run a single assessment step with progress updates"""
        try:
            self.status_bar.showMessage(f"Running {step_name}...")
            self.scan_status_label.setText(f"Status: {step_name}")
            
            # Execute the scan
            result = scan_function()
            
            self.status_bar.showMessage(f"✅ {step_name} completed")
            return result
            
        except Exception as e:
            self.status_bar.showMessage(f"⚠️ {step_name} failed: {str(e)}")
            return None
    
    def stop_scan(self):
        """Stop current scan"""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.terminate()
            self.scan_worker.wait()
        
        self.scan_status_label.setText("Status: Scan stopped")
        self.progress_bar.setVisible(False)
        self.status_bar.showMessage("⏹️ Scan stopped by user")
    
    def show_settings(self):
        """Show settings dialog"""
        QMessageBox.information(self, "Settings", "Settings dialog will be implemented in future version")
    
    def show_user_guide(self):
        """Show user guide"""
        QMessageBox.information(self, "User Guide", 
                              "User guide is available in the 'docs' folder.\n\n"
                              "Quick Start:\n"
                              "1. Enter target in the header\n"
                              "2. Select scan type from tabs\n"
                              "3. Configure options\n"
                              "4. Click Start Scan")
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, "About StrikeSuite",
                         "🚀 StrikeSuite v1.0\n\n"
                         "Advanced Penetration Testing Toolkit\n\n"
                         "Features:\n"
                         "• Network scanning\n"
                         "• Vulnerability assessment\n"
                         "• API security testing\n"
                         "• Brute force testing\n"
                         "• Exploitation testing\n"
                         "• Post-exploitation analysis\n\n"
                         "⚠️ Use only on systems you own or have explicit permission to test")
    
    # Copy-Paste functionality
    def copy_selection(self):
        """Copy selected text to clipboard"""
        try:
            # Get the currently focused widget
            focused_widget = self.focusWidget()
            
            if hasattr(focused_widget, 'selectedText'):
                # For text widgets with selectedText method
                selected_text = focused_widget.selectedText()
                if selected_text:
                    from PyQt5.QtWidgets import QApplication
                    clipboard = QApplication.clipboard()
                    clipboard.setText(selected_text)
                    self.status_bar.showMessage(f"📋 Copied {len(selected_text)} characters to clipboard")
                else:
                    self.status_bar.showMessage("⚠️ No text selected")
            elif hasattr(focused_widget, 'text'):
                # For widgets with text method (like QLineEdit)
                text = focused_widget.text()
                if text:
                    from PyQt5.QtWidgets import QApplication
                    clipboard = QApplication.clipboard()
                    clipboard.setText(text)
                    self.status_bar.showMessage(f"📋 Copied text to clipboard")
                else:
                    self.status_bar.showMessage("⚠️ No text to copy")
            else:
                self.status_bar.showMessage("⚠️ Cannot copy from this widget")
                
        except Exception as e:
            self.status_bar.showMessage(f"❌ Copy failed: {str(e)}")
    
    def paste_content(self):
        """Paste content from clipboard"""
        try:
            from PyQt5.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            text = clipboard.text()
            
            if text:
                # Get the currently focused widget
                focused_widget = self.focusWidget()
                
                if hasattr(focused_widget, 'setText'):
                    # For widgets with setText method (like QLineEdit)
                    focused_widget.setText(text)
                    self.status_bar.showMessage(f"📄 Pasted {len(text)} characters")
                elif hasattr(focused_widget, 'insertPlainText'):
                    # For text widgets with insertPlainText method
                    focused_widget.insertPlainText(text)
                    self.status_bar.showMessage(f"📄 Pasted {len(text)} characters")
                elif hasattr(focused_widget, 'append'):
                    # For widgets with append method
                    focused_widget.append(text)
                    self.status_bar.showMessage(f"📄 Pasted {len(text)} characters")
                else:
                    self.status_bar.showMessage("⚠️ Cannot paste to this widget")
            else:
                self.status_bar.showMessage("⚠️ Clipboard is empty")
                
        except Exception as e:
            self.status_bar.showMessage(f"❌ Paste failed: {str(e)}")
    
    def select_all_content(self):
        """Select all text in the current widget"""
        try:
            focused_widget = self.focusWidget()
            
            if hasattr(focused_widget, 'selectAll'):
                focused_widget.selectAll()
                self.status_bar.showMessage("🔍 All text selected")
            elif hasattr(focused_widget, 'setSelection'):
                # For text widgets
                focused_widget.setSelection(0, len(focused_widget.toPlainText()))
                self.status_bar.showMessage("🔍 All text selected")
            else:
                self.status_bar.showMessage("⚠️ Cannot select text in this widget")
                
        except Exception as e:
            self.status_bar.showMessage(f"❌ Select all failed: {str(e)}")
    
    def clear_content(self):
        """Clear content in the current widget"""
        try:
            focused_widget = self.focusWidget()
            
            if hasattr(focused_widget, 'clear'):
                focused_widget.clear()
                self.status_bar.showMessage("🗑️ Content cleared")
            elif hasattr(focused_widget, 'setText'):
                focused_widget.setText("")
                self.status_bar.showMessage("🗑️ Content cleared")
            else:
                self.status_bar.showMessage("⚠️ Cannot clear this widget")
                
        except Exception as e:
            self.status_bar.showMessage(f"❌ Clear failed: {str(e)}")
    
    def toggle_fullscreen(self):
        """Toggle full screen mode"""
        try:
            if not self.is_fullscreen:
                # Enter full screen
                self.original_geometry = self.geometry()
                self.showFullScreen()
                self.is_fullscreen = True
                self.fullscreen_action.setText('🖥️ Exit Full Screen')
                self.status_bar.showMessage("🖥️ Full screen mode activated - Press F11 or ESC to exit")
            else:
                # Exit full screen
                self.showNormal()
                if self.original_geometry:
                    self.setGeometry(self.original_geometry)
                self.is_fullscreen = False
                self.fullscreen_action.setText('🖥️ Toggle Full Screen')
                self.status_bar.showMessage("🖥️ Full screen mode deactivated")
                
        except Exception as e:
            self.status_bar.showMessage(f"❌ Full screen toggle failed: {str(e)}")
    
    def scroll_down(self):
        """Scroll down in the current tab"""
        try:
            current_tab = self.tab_widget.currentWidget()
            if current_tab:
                # Find scrollable widgets in the current tab
                scrollable_widgets = self.find_scrollable_widgets(current_tab)
                for widget in scrollable_widgets:
                    if hasattr(widget, 'verticalScrollBar'):
                        scrollbar = widget.verticalScrollBar()
                        if scrollbar:
                            scrollbar.setValue(scrollbar.value() + 50)
                            self.status_bar.showMessage("⬇️ Scrolled down")
                            return
                self.status_bar.showMessage("⚠️ No scrollable content found")
            else:
                self.status_bar.showMessage("⚠️ No active tab")
                
        except Exception as e:
            self.status_bar.showMessage(f"❌ Scroll down failed: {str(e)}")
    
    def scroll_up(self):
        """Scroll up in the current tab"""
        try:
            current_tab = self.tab_widget.currentWidget()
            if current_tab:
                # Find scrollable widgets in the current tab
                scrollable_widgets = self.find_scrollable_widgets(current_tab)
                for widget in scrollable_widgets:
                    if hasattr(widget, 'verticalScrollBar'):
                        scrollbar = widget.verticalScrollBar()
                        if scrollbar:
                            scrollbar.setValue(max(0, scrollbar.value() - 50))
                            self.status_bar.showMessage("⬆️ Scrolled up")
                            return
                self.status_bar.showMessage("⚠️ No scrollable content found")
            else:
                self.status_bar.showMessage("⚠️ No active tab")
                
        except Exception as e:
            self.status_bar.showMessage(f"❌ Scroll up failed: {str(e)}")
    
    def find_scrollable_widgets(self, widget):
        """Find all scrollable widgets in a widget hierarchy"""
        scrollable_widgets = []
        
        def search_widgets(w):
            if hasattr(w, 'verticalScrollBar') and w.verticalScrollBar().isVisible():
                scrollable_widgets.append(w)
            if hasattr(w, 'children'):
                for child in w.children():
                    if hasattr(child, 'verticalScrollBar'):
                        search_widgets(child)
        
        search_widgets(widget)
        return scrollable_widgets
    
    def keyPressEvent(self, event):
        """Handle key press events for full screen and scroll"""
        if event.key() == Qt.Key_F11:
            self.toggle_fullscreen()
        elif event.key() == Qt.Key_Escape and self.is_fullscreen:
            self.toggle_fullscreen()
        elif event.modifiers() == Qt.ControlModifier:
            if event.key() == Qt.Key_Down:
                self.scroll_down()
            elif event.key() == Qt.Key_Up:
                self.scroll_up()
        else:
            super().keyPressEvent(event)
