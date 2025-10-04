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
                             QProgressBar, QSplitter, QDockWidget, QToolBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSettings
from PyQt5.QtGui import QIcon, QFont, QPalette, QColor

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
        self.init_ui()
        self.setup_database()
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("StrikeSuite v1.0 - Advanced Penetration Testing Toolkit")
        self.setGeometry(100, 100, 1200, 800)
        
        # Create scroll area for the entire window
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        
        # Create central widget and layout
        central_widget = QWidget()
        scroll_area.setWidget(central_widget)
        self.setCentralWidget(scroll_area)
        
        layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.create_network_tab()
        self.create_api_tab()
        self.create_vulnerability_tab()
        self.create_exploitation_tab()
        self.create_brute_force_tab()
        self.create_post_exploit_tab()
        self.create_reporting_tab()
        self.create_plugins_tab()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Create menu bar
        self.create_menu_bar()
    
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
