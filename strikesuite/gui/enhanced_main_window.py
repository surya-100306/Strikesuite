#!/usr/bin/env python3
"""
Enhanced StrikeSuite Main Window
Modern GUI with advanced features and improved user experience
"""

import sys
import os
import json
import datetime
from pathlib import Path
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, 
                             QVBoxLayout, QHBoxLayout, QWidget, QLabel,
                             QPushButton, QTextEdit, QStatusBar, QMenuBar,
                             QAction, QMessageBox, QFileDialog, QScrollArea,
                             QProgressBar, QSplitter, QDockWidget, QToolBar,
                             QLineEdit, QScrollBar, QFrame, QSystemTrayIcon,
                             QSplashScreen, QDesktopWidget, QGraphicsDropShadowEffect,
                             QGroupBox, QGridLayout, QComboBox, QSpinBox,
                             QCheckBox, QSlider, QDial, QProgressDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSettings, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import (QIcon, QFont, QPalette, QColor, QKeySequence, QPixmap,
                         QPainter, QLinearGradient, QRadialGradient, QBrush)

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

class ModernTheme:
    """Modern theme configuration for the application"""
    
    # Color palette
    PRIMARY_COLOR = "#2c3e50"
    SECONDARY_COLOR = "#3498db"
    SUCCESS_COLOR = "#27ae60"
    WARNING_COLOR = "#f39c12"
    DANGER_COLOR = "#e74c3c"
    INFO_COLOR = "#17a2b8"
    
    # Background colors
    BG_PRIMARY = "#ffffff"
    BG_SECONDARY = "#f8f9fa"
    BG_DARK = "#2c3e50"
    BG_LIGHT = "#ecf0f1"
    
    # Text colors
    TEXT_PRIMARY = "#2c3e50"
    TEXT_SECONDARY = "#6c757d"
    TEXT_LIGHT = "#ffffff"
    
    # Border colors
    BORDER_LIGHT = "#dee2e6"
    BORDER_DARK = "#495057"
    
    @staticmethod
    def get_button_style(color, hover_color=None):
        """Get modern button styling"""
        if hover_color is None:
            hover_color = color
        return f"""
        QPushButton {{
            background-color: {color};
            color: white;
            border: none;
            border-radius: 8px;
            padding: 12px 24px;
            font-size: 14px;
            font-weight: bold;
            min-height: 20px;
        }}
        QPushButton:hover {{
            background-color: {hover_color};
            transform: translateY(-2px);
        }}
        QPushButton:pressed {{
            background-color: {color};
            transform: translateY(0px);
        }}
        QPushButton:disabled {{
            background-color: #6c757d;
            color: #ffffff;
        }}
        """
    
    @staticmethod
    def get_card_style():
        """Get modern card styling"""
        return """
        QGroupBox {
            background-color: #ffffff;
            border: 1px solid #dee2e6;
            border-radius: 12px;
            margin-top: 10px;
            padding-top: 15px;
            font-weight: bold;
            font-size: 14px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 15px;
            padding: 0 10px 0 10px;
            color: #2c3e50;
            font-size: 16px;
            font-weight: bold;
        }
        """
    
    @staticmethod
    def get_input_style():
        """Get modern input styling"""
        return """
        QLineEdit, QTextEdit, QComboBox, QSpinBox {
            border: 2px solid #dee2e6;
            border-radius: 8px;
            padding: 10px;
            background-color: #ffffff;
            font-size: 14px;
            min-height: 20px;
        }
        QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus {
            border-color: #3498db;
            background-color: #f8f9fa;
        }
        QLineEdit:hover, QTextEdit:hover, QComboBox:hover, QSpinBox:hover {
            border-color: #adb5bd;
        }
        """

class EnhancedMainWindow(QMainWindow):
    """Enhanced main application window with modern design"""
    
    # Signals
    scan_started = pyqtSignal(str)
    scan_completed = pyqtSignal(dict)
    status_updated = pyqtSignal(str)
    
    def __init__(self, plugin_manager=None):
        super().__init__()
        self.plugin_manager = plugin_manager
        self.scan_worker = None
        self.is_fullscreen = False
        self.original_geometry = None
        self.settings = QSettings("StrikeSuite", "MainWindow")
        self.theme = ModernTheme()
        
        # Initialize UI with modern design
        self.init_modern_ui()
        self.setup_database()
        self.setup_animations()
        self.load_settings()
        
    def init_modern_ui(self):
        """Initialize modern user interface"""
        self.setWindowTitle("StrikeSuite v2.0 - Advanced Penetration Testing Toolkit")
        self.setGeometry(100, 100, 1400, 900)
        
        # Set modern window properties
        self.setWindowFlags(Qt.Window | Qt.WindowCloseButtonHint | Qt.WindowMinimizeButtonHint)
        
        # Apply modern styling
        self.setStyleSheet(self.get_modern_stylesheet())
        
        # Create central widget with modern layout
        self.create_central_widget()
        
        # Create modern menu bar
        self.create_modern_menu_bar()
        
        # Create modern toolbar
        self.create_modern_toolbar()
        
        # Create modern status bar
        self.create_modern_status_bar()
        
        # Create dock widgets for advanced features
        self.create_dock_widgets()
        
        # Apply modern effects
        self.apply_modern_effects()
    
    def create_central_widget(self):
        """Create modern central widget"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout with modern spacing
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Create welcome section
        self.create_welcome_section(main_layout)
        
        # Create modern tab widget
        self.create_modern_tab_widget(main_layout)
        
        # Create dashboard section
        self.create_dashboard_section(main_layout)
    
    def create_welcome_section(self, layout):
        """Create modern welcome section"""
        welcome_frame = QFrame()
        welcome_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #667eea, stop:1 #764ba2);
                border-radius: 15px;
                padding: 20px;
            }
        """)
        welcome_layout = QVBoxLayout(welcome_frame)
        
        # Title with modern styling
        title_label = QLabel("StrikeSuite v2.0")
        title_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 32px;
                font-weight: bold;
                padding: 10px;
            }
        """)
        welcome_layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("Advanced Cybersecurity Testing Framework")
        subtitle_label.setStyleSheet("""
            QLabel {
                color: rgba(255, 255, 255, 0.9);
                font-size: 16px;
                padding: 5px 10px;
            }
        """)
        welcome_layout.addWidget(subtitle_label)
        
        # Quick actions
        self.create_quick_actions(welcome_layout)
        
        layout.addWidget(welcome_frame)
    
    def create_quick_actions(self, layout):
        """Create quick action buttons"""
        actions_layout = QHBoxLayout()
        
        # Quick scan button
        quick_scan_btn = QPushButton("Quick Scan")
        quick_scan_btn.setStyleSheet(self.theme.get_button_style(self.theme.SUCCESS_COLOR))
        quick_scan_btn.clicked.connect(self.quick_scan)
        actions_layout.addWidget(quick_scan_btn)
        
        # Full assessment button
        full_assessment_btn = QPushButton("Full Assessment")
        full_assessment_btn.setStyleSheet(self.theme.get_button_style(self.theme.PRIMARY_COLOR))
        full_assessment_btn.clicked.connect(self.full_assessment)
        actions_layout.addWidget(full_assessment_btn)
        
        # Report generation button
        report_btn = QPushButton("Generate Report")
        report_btn.setStyleSheet(self.theme.get_button_style(self.theme.INFO_COLOR))
        report_btn.clicked.connect(self.generate_report)
        actions_layout.addWidget(report_btn)
        
        # Settings button
        settings_btn = QPushButton("Settings")
        settings_btn.setStyleSheet(self.theme.get_button_style(self.theme.SECONDARY_COLOR))
        settings_btn.clicked.connect(self.show_settings)
        actions_layout.addWidget(settings_btn)
        
        layout.addLayout(actions_layout)
    
    def create_modern_tab_widget(self, layout):
        """Create modern tab widget"""
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #dee2e6;
                border-radius: 8px;
                background-color: #ffffff;
            }
            QTabBar::tab {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                padding: 12px 20px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
            QTabBar::tab:selected {
                background-color: #ffffff;
                border-bottom: 1px solid #ffffff;
            }
            QTabBar::tab:hover {
                background-color: #e9ecef;
            }
        """)
        
        # Import and add tabs
        self.add_modern_tabs()
        
        layout.addWidget(self.tab_widget)
    
    def add_modern_tabs(self):
        """Add modern tabs with enhanced functionality"""
        try:
            # Network scanning tab
            from strikesuite.gui.network_tab import NetworkTab
            network_tab = NetworkTab()
            self.tab_widget.addTab(network_tab, "Network")
            
            # API testing tab
            from strikesuite.gui.api_tab import APITab
            api_tab = APITab()
            self.tab_widget.addTab(api_tab, "API Testing")
            
            # Vulnerability scanning tab
            from strikesuite.gui.vulnerability_tab import VulnerabilityTab
            vuln_tab = VulnerabilityTab()
            self.tab_widget.addTab(vuln_tab, "Vulnerabilities")
            
            # Exploitation tab
            from strikesuite.gui.exploitation_tab import ExploitationTab
            exploit_tab = ExploitationTab()
            self.tab_widget.addTab(exploit_tab, "Exploitation")
            
            # Brute force tab
            from strikesuite.gui.brute_force_tab import BruteForceTab
            brute_tab = BruteForceTab()
            self.tab_widget.addTab(brute_tab, "Brute Force")
            
            # Post-exploitation tab
            from strikesuite.gui.post_exploit_tab import PostExploitTab
            post_exploit_tab = PostExploitTab()
            self.tab_widget.addTab(post_exploit_tab, "Post-Exploit")
            
            # Reporting tab
            from strikesuite.gui.reporting_tab import ReportingTab
            reporting_tab = ReportingTab()
            self.tab_widget.addTab(reporting_tab, "Reports")
            
            # Plugins tab
            from strikesuite.gui.plugins_tab import PluginsTab
            plugins_tab = PluginsTab()
            self.tab_widget.addTab(plugins_tab, "Plugins")
            
            # CVE Training tab
            from strikesuite.gui.cve_training_tab import CVETrainingTab
            cve_tab = CVETrainingTab()
            self.tab_widget.addTab(cve_tab, "CVE Training")
            
        except ImportError as e:
            print(f"Warning: Could not import some tabs: {e}")
            # Add placeholder tabs
            self.add_placeholder_tabs()
    
    def add_placeholder_tabs(self):
        """Add placeholder tabs when imports fail"""
        placeholder_tabs = [
            ("Network", "Network scanning and discovery"),
            ("API Testing", "API security testing"),
            ("Vulnerabilities", "Vulnerability assessment"),
            ("Exploitation", "Exploitation tools"),
            ("Brute Force", "Brute force attacks"),
            ("Post-Exploit", "Post-exploitation activities"),
            ("Reports", "Report generation"),
            ("Plugins", "Plugin management"),
            ("CVE Training", "CVE training system")
        ]
        
        for title, description in placeholder_tabs:
            placeholder = QWidget()
            layout = QVBoxLayout(placeholder)
            
            label = QLabel(f"<h2>{title}</h2><p>{description}</p>")
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet("color: #6c757d; font-size: 16px;")
            layout.addWidget(label)
            
            self.tab_widget.addTab(placeholder, title)
    
    def create_dashboard_section(self, layout):
        """Create modern dashboard section"""
        dashboard_group = QGroupBox("Dashboard")
        dashboard_group.setStyleSheet(self.theme.get_card_style())
        dashboard_layout = QGridLayout(dashboard_group)
        
        # Dashboard metrics
        self.create_dashboard_metrics(dashboard_layout)
        
        layout.addWidget(dashboard_group)
    
    def create_dashboard_metrics(self, layout):
        """Create dashboard metrics cards"""
        metrics = [
            ("Active Scans", "0", self.theme.INFO_COLOR),
            ("Vulnerabilities", "0", self.theme.WARNING_COLOR),
            ("Hosts Found", "0", self.theme.SUCCESS_COLOR),
            ("Reports Generated", "0", self.theme.PRIMARY_COLOR)
        ]
        
        for i, (title, value, color) in enumerate(metrics):
            metric_widget = self.create_metric_card(title, value, color)
            layout.addWidget(metric_widget, 0, i)
    
    def create_metric_card(self, title, value, color):
        """Create a metric card widget"""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: #ffffff;
                border: 1px solid #dee2e6;
                border-radius: 12px;
                padding: 20px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        
        # Value
        value_label = QLabel(value)
        value_label.setStyleSheet(f"""
            QLabel {{
                color: {color};
                font-size: 32px;
                font-weight: bold;
                text-align: center;
            }}
        """)
        value_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(value_label)
        
        # Title
        title_label = QLabel(title)
        title_label.setStyleSheet("""
            QLabel {
                color: #6c757d;
                font-size: 14px;
                text-align: center;
            }
        """)
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        return card
    
    def create_modern_menu_bar(self):
        """Create modern menu bar"""
        menubar = self.menuBar()
        menubar.setStyleSheet("""
            QMenuBar {
                background-color: #f8f9fa;
                border-bottom: 1px solid #dee2e6;
                padding: 5px;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QMenuBar::item:selected {
                background-color: #e9ecef;
            }
        """)
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        new_project_action = QAction('New Project', self)
        new_project_action.setShortcut('Ctrl+N')
        new_project_action.triggered.connect(self.new_project)
        file_menu.addAction(new_project_action)
        
        open_project_action = QAction('Open Project', self)
        open_project_action.setShortcut('Ctrl+O')
        open_project_action.triggered.connect(self.open_project)
        file_menu.addAction(open_project_action)
        
        file_menu.addSeparator()
        
        save_action = QAction('Save', self)
        save_action.setShortcut('Ctrl+S')
        save_action.triggered.connect(self.save_project)
        file_menu.addAction(save_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        
        quick_scan_action = QAction('Quick Scan', self)
        quick_scan_action.setShortcut('F5')
        quick_scan_action.triggered.connect(self.quick_scan)
        tools_menu.addAction(quick_scan_action)
        
        full_assessment_action = QAction('Full Assessment', self)
        full_assessment_action.setShortcut('F6')
        full_assessment_action.triggered.connect(self.full_assessment)
        tools_menu.addAction(full_assessment_action)
        
        tools_menu.addSeparator()
        
        # Full screen toggle
        self.fullscreen_action = QAction('Toggle Full Screen', self)
        self.fullscreen_action.setShortcut('F11')
        self.fullscreen_action.triggered.connect(self.toggle_fullscreen)
        tools_menu.addAction(self.fullscreen_action)
        
        # View menu
        view_menu = menubar.addMenu('View')
        
        dashboard_action = QAction('Dashboard', self)
        dashboard_action.triggered.connect(self.show_dashboard)
        view_menu.addAction(dashboard_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_modern_toolbar(self):
        """Create modern toolbar"""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setStyleSheet("""
            QToolBar {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                spacing: 5px;
                padding: 5px;
            }
            QToolButton {
                background-color: transparent;
                border: 1px solid transparent;
                border-radius: 6px;
                padding: 8px;
                margin: 2px;
            }
            QToolButton:hover {
                background-color: #e9ecef;
                border-color: #dee2e6;
            }
            QToolButton:pressed {
                background-color: #dee2e6;
            }
        """)
        
        # Add toolbar actions
        quick_scan_btn = toolbar.addAction("Quick Scan", self.quick_scan)
        quick_scan_btn.setToolTip("Quick Scan (F5)")
        
        full_assessment_btn = toolbar.addAction("Full Assessment", self.full_assessment)
        full_assessment_btn.setToolTip("Full Assessment (F6)")
        
        toolbar.addSeparator()
        
        report_btn = toolbar.addAction("Generate Report", self.generate_report)
        report_btn.setToolTip("Generate Report")
        
        settings_btn = toolbar.addAction("Settings", self.show_settings)
        settings_btn.setToolTip("Settings")
        
        self.addToolBar(toolbar)
    
    def create_modern_status_bar(self):
        """Create modern status bar"""
        self.status_bar = QStatusBar()
        self.status_bar.setStyleSheet("""
            QStatusBar {
                background-color: #f8f9fa;
                border-top: 1px solid #dee2e6;
                padding: 5px;
            }
            QStatusBar::item {
                border: none;
            }
        """)
        
        # Status label
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #28a745; font-weight: bold;")
        self.status_bar.addWidget(self.status_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #dee2e6;
                border-radius: 4px;
                text-align: center;
                background-color: #ffffff;
            }
            QProgressBar::chunk {
                background-color: #28a745;
                border-radius: 3px;
            }
        """)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
        # Time label
        self.time_label = QLabel()
        self.time_label.setStyleSheet("color: #6c757d;")
        self.status_bar.addPermanentWidget(self.time_label)
        
        self.setStatusBar(self.status_bar)
        
        # Update time
        self.time_timer = QTimer()
        self.time_timer.timeout.connect(self.update_time)
        self.time_timer.start(1000)
        self.update_time()
    
    def create_dock_widgets(self):
        """Create dock widgets for advanced features"""
        # Log dock widget
        self.log_dock = QDockWidget("Activity Log", self)
        self.log_dock.setStyleSheet("""
            QDockWidget {
                background-color: #ffffff;
                border: 1px solid #dee2e6;
                titlebar-close-icon: url(close.png);
                titlebar-normal-icon: url(normal.png);
            }
            QDockWidget::title {
                background-color: #f8f9fa;
                padding: 5px;
                border-bottom: 1px solid #dee2e6;
            }
        """)
        
        self.log_text = QTextEdit()
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: #ffffff;
                border: none;
                font-family: 'Consolas', monospace;
                font-size: 12px;
            }
        """)
        self.log_dock.setWidget(self.log_text)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.log_dock)
    
    def apply_modern_effects(self):
        """Apply modern visual effects"""
        # Add shadow effect to main window
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 30))
        shadow.setOffset(0, 5)
        self.centralWidget().setGraphicsEffect(shadow)
    
    def get_modern_stylesheet(self):
        """Get comprehensive modern stylesheet"""
        return f"""
        QMainWindow {{
            background-color: {self.theme.BG_SECONDARY};
        }}
        
        QWidget {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }}
        
        QScrollBar:vertical {{
            background-color: #f1f1f1;
            width: 12px;
            border-radius: 6px;
        }}
        
        QScrollBar::handle:vertical {{
            background-color: #c1c1c1;
            border-radius: 6px;
            min-height: 20px;
        }}
        
        QScrollBar::handle:vertical:hover {{
            background-color: #a8a8a8;
        }}
        
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0px;
        }}
        
        QScrollBar:horizontal {{
            background-color: #f1f1f1;
            height: 12px;
            border-radius: 6px;
        }}
        
        QScrollBar::handle:horizontal {{
            background-color: #c1c1c1;
            border-radius: 6px;
            min-width: 20px;
        }}
        
        QScrollBar::handle:horizontal:hover {{
            background-color: #a8a8a8;
        }}
        
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
            width: 0px;
        }}
        """
    
    def setup_animations(self):
        """Setup modern animations"""
        self.animation_timer = QTimer()
        self.animation_timer.timeout.connect(self.update_animations)
        self.animation_timer.start(16)  # 60 FPS
    
    def update_animations(self):
        """Update animations"""
        # Add any continuous animations here
        pass
    
    def load_settings(self):
        """Load application settings"""
        geometry = self.settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)
        
        window_state = self.settings.value("windowState")
        if window_state:
            self.restoreState(window_state)
    
    def save_settings(self):
        """Save application settings"""
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("windowState", self.saveState())
    
    def update_time(self):
        """Update time display"""
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.setText(current_time)
    
    def log_message(self, message, level="INFO"):
        """Log message to activity log"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        color = {
            "INFO": "#17a2b8",
            "SUCCESS": "#28a745", 
            "WARNING": "#ffc107",
            "ERROR": "#dc3545"
        }.get(level, "#6c757d")
        
        formatted_message = f'<span style="color: {color}">[{timestamp}] {level}: {message}</span>'
        self.log_text.append(formatted_message)
        
        # Auto-scroll to bottom
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    # Enhanced functionality methods
    def new_project(self):
        """Create new project"""
        self.log_message("Creating new project...", "INFO")
        # Implementation for new project
        
    def open_project(self):
        """Open existing project"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Project", "", "StrikeSuite Projects (*.ssp)"
        )
        if file_path:
            self.log_message(f"Opening project: {file_path}", "INFO")
            # Implementation for opening project
    
    def save_project(self):
        """Save current project"""
        self.log_message("Saving project...", "INFO")
        # Implementation for saving project
    
    def quick_scan(self):
        """Perform quick scan"""
        self.log_message("Starting quick scan...", "INFO")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        # Implementation for quick scan
        QTimer.singleShot(2000, self.quick_scan_completed)
    
    def quick_scan_completed(self):
        """Quick scan completed"""
        self.progress_bar.setVisible(False)
        self.log_message("Quick scan completed", "SUCCESS")
        self.status_label.setText("Quick scan completed")
    
    def full_assessment(self):
        """Perform full assessment"""
        self.log_message("Starting full assessment...", "INFO")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 100)
        
        # Implementation for full assessment
        QTimer.singleShot(3000, self.full_assessment_completed)
    
    def full_assessment_completed(self):
        """Full assessment completed"""
        self.progress_bar.setVisible(False)
        self.log_message("Full assessment completed", "SUCCESS")
        self.status_label.setText("Full assessment completed")
    
    def generate_report(self):
        """Generate comprehensive report"""
        self.log_message("Generating report...", "INFO")
        # Implementation for report generation
    
    def show_settings(self):
        """Show settings dialog"""
        self.log_message("Opening settings...", "INFO")
        # Implementation for settings dialog
    
    def show_dashboard(self):
        """Show dashboard"""
        self.log_message("Opening dashboard...", "INFO")
        # Implementation for dashboard
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, "About StrikeSuite", 
                         "StrikeSuite v2.0\nAdvanced Cybersecurity Testing Framework\n\n"
                         "A comprehensive security testing platform with modern GUI.")
    
    def toggle_fullscreen(self):
        """Toggle full screen mode"""
        if not self.is_fullscreen:
            self.original_geometry = self.geometry()
            self.showFullScreen()
            self.is_fullscreen = True
            self.fullscreen_action.setText('Exit Full Screen')
            self.log_message("Entered full screen mode", "INFO")
        else:
            self.showNormal()
            if self.original_geometry:
                self.setGeometry(self.original_geometry)
            self.is_fullscreen = False
            self.fullscreen_action.setText('Toggle Full Screen')
            self.log_message("Exited full screen mode", "INFO")
    
    def setup_database(self):
        """Setup database connection"""
        try:
            from strikesuite.utils.db_utils import init_db
            init_db()
            self.log_message("Database initialized successfully", "SUCCESS")
        except Exception as e:
            self.log_message(f"Database initialization failed: {e}", "ERROR")
    
    def closeEvent(self, event):
        """Handle application close"""
        self.save_settings()
        self.log_message("Application closing...", "INFO")
        event.accept()

# Enhanced application class
class EnhancedStrikeSuiteApp(QApplication):
    """Enhanced application class with modern features"""
    
    def __init__(self, argv):
        super().__init__(argv)
        self.setApplicationName("StrikeSuite")
        self.setApplicationVersion("2.0.0")
        self.setOrganizationName("StrikeSuite Team")
        
        # Set modern application properties
        self.setStyle('Fusion')  # Modern style
        
        # Create splash screen
        self.create_splash_screen()
        
        # Create main window
        self.main_window = EnhancedMainWindow()
        
        # Hide splash screen
        self.splash.finish(self.main_window)
        self.splash.deleteLater()
        
        # Show main window
        self.main_window.show()
    
    def create_splash_screen(self):
        """Create modern splash screen"""
        # Create splash screen widget
        self.splash = QSplashScreen()
        self.splash.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.SplashScreen)
        
        # Create splash screen content
        splash_widget = QWidget()
        splash_layout = QVBoxLayout(splash_widget)
        
        # Title
        title_label = QLabel("StrikeSuite v2.0")
        title_label.setStyleSheet("""
            QLabel {
                color: #2c3e50;
                font-size: 36px;
                font-weight: bold;
                text-align: center;
            }
        """)
        title_label.setAlignment(Qt.AlignCenter)
        splash_layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("Advanced Cybersecurity Testing Framework")
        subtitle_label.setStyleSheet("""
            QLabel {
                color: #6c757d;
                font-size: 18px;
                text-align: center;
            }
        """)
        subtitle_label.setAlignment(Qt.AlignCenter)
        splash_layout.addWidget(subtitle_label)
        
        # Progress bar
        progress_bar = QProgressBar()
        progress_bar.setRange(0, 0)  # Indeterminate
        progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #dee2e6;
                border-radius: 8px;
                text-align: center;
                background-color: #ffffff;
            }
            QProgressBar::chunk {
                background-color: #28a745;
                border-radius: 6px;
            }
        """)
        splash_layout.addWidget(progress_bar)
        
        self.splash.setWidget(splash_widget)
        self.splash.show()
        
        # Show splash screen for minimum time
        QTimer.singleShot(2000, lambda: None)

def main():
    """Main application entry point"""
    app = EnhancedStrikeSuiteApp(sys.argv)
    return app.exec_()

if __name__ == "__main__":
    sys.exit(main())

