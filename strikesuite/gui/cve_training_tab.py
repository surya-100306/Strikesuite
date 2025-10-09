#!/usr/bin/env python3
"""
CVE Training Tab
GUI for CVE training system with database, modules, and educational features
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QLineEdit, QPushButton, QTextEdit,
                             QCheckBox, QGroupBox, QTableWidget, QTableWidgetItem,
                             QHeaderView, QSpinBox, QComboBox, QScrollArea,
                             QFileDialog, QListWidget, QListWidgetItem, QTabWidget,
                             QProgressBar, QSlider, QFrame, QSplitter, QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QPixmap, QIcon, QColor
import time
import json

# Import core modules
import sys
from pathlib import Path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

class CVETrainingTab(QWidget):
    """CVE Training system tab widget"""
    
    def __init__(self):
        super().__init__()
        self.current_module = None
        self.current_quiz = None
        self.quiz_answers = []
        self.scroll_area = None
        
        # Initialize CVE trainer
        try:
            from core.cve_trainer import CVETrainer
            self.cve_trainer = CVETrainer()
        except Exception as e:
            print(f"Error initializing CVE trainer: {e}")
            self.cve_trainer = None
        
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
                background-color: #9b59b6;
                border-radius: 8px;
                min-height: 30px;
                margin: 2px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #8e44ad;
            }
            QScrollBar::handle:vertical:pressed {
                background-color: #7d3c98;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
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
        
        # Create main tab widget
        self.main_tabs = QTabWidget()
        self.main_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #9b59b6;
                border-radius: 8px;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #e8e8e8;
                color: #2c3e50;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: #9b59b6;
                color: white;
            }
            QTabBar::tab:hover {
                background-color: #8e44ad;
                color: white;
            }
        """)
        
        # Create tabs
        self.create_cve_database_tab()
        self.create_training_modules_tab()
        self.create_quiz_system_tab()
        self.create_progress_tracking_tab()
        
        layout.addWidget(self.main_tabs)
        
        # Set up keyboard shortcuts for scrolling
        self.setup_keyboard_shortcuts()
        
        # Load filter options
        self.load_filter_options()
        
    def create_welcome_section(self, layout):
        """Create welcome section with CVE training overview"""
        welcome_widget = QWidget()
        welcome_widget.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #9b59b6, stop:1 #8e44ad);
                border-radius: 10px;
                padding: 15px;
            }
            QLabel {
                color: white;
                font-size: 12px;
            }
        """)
        
        welcome_layout = QVBoxLayout(welcome_widget)
        
        # Welcome text
        welcome_text = QLabel("🎓 CVE TRAINING SYSTEM - MASTER VULNERABILITY ANALYSIS")
        welcome_text.setStyleSheet("font-size: 16px; font-weight: bold; color: white;")
        welcome_layout.addWidget(welcome_text)
        
        # Features list
        features_text = QLabel("""
        <h3>🎯 Enhanced CVE Training & Easy Identification Features:</h3>
        <ul>
        <li>✅ <b>Easy CVE Identification:</b> Quick buttons to show all CVEs, critical CVEs, recent CVEs</li>
        <li>✅ <b>Advanced Search & Filters:</b> Search by CVE ID, description, vendor, product, severity, category</li>
        <li>✅ <b>Comprehensive CVE Database:</b> 1000+ vulnerabilities with detailed information</li>
        <li>✅ <b>Interactive Training Modules:</b> CVE Fundamentals, CVSS, Critical CVEs, Exploit Development</li>
        <li>✅ <b>Dynamic Quiz System:</b> Test your knowledge with progress tracking</li>
        <li>✅ <b>Critical CVE Analysis:</b> Heartbleed, Log4Shell, EternalBlue, Shellshock, and more!</li>
        <li>✅ <b>Real-time CVE Search:</b> Instant vulnerability analysis and remediation guidance</li>
        <li>✅ <b>Security Recommendations:</b> Automated security guidance based on CVE analysis</li>
        <li>✅ <b>Progress Tracking:</b> Monitor your learning progress and achievements</li>
        <li>✅ <b>Full Page Scrolling:</b> Navigate easily with ⬆️⬇️ buttons and keyboard shortcuts</li>
        </ul>
        <p><b>🚀 Quick Start:</b> Click "Show All CVEs" to see everything, or "Critical CVEs Only" for immediate threats!</p>
        <p><b>🎯 Easy Identification:</b> Use the quick identification buttons to instantly find what you need!</p>
        <p><b>📜 Scroll Controls:</b> Use ⬆️⬇️ buttons or keyboard shortcuts (Ctrl+Home/End, PgUp/PgDown)</p>
        """)
        features_text.setWordWrap(True)
        features_text.setStyleSheet("font-size: 11px; color: #ecf0f1;")
        welcome_layout.addWidget(features_text)
        
        layout.addWidget(welcome_widget)
    
    def create_cve_database_tab(self):
        """Create CVE database tab"""
        cve_tab = QWidget()
        layout = QVBoxLayout(cve_tab)
        
        # Quick Identification Section
        quick_id_group = QGroupBox("🎯 Quick CVE Identification")
        quick_id_group.setStyleSheet("""
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
        quick_id_layout = QGridLayout(quick_id_group)
        
        # Quick access buttons
        self.show_all_btn = QPushButton("📋 Show All CVEs")
        self.show_all_btn.clicked.connect(self.show_all_cves)
        self.show_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                font-weight: bold;
                padding: 8px;
                border-radius: 4px;
                border: none;
            }
            QPushButton:hover { background-color: #2980b9; }
        """)
        quick_id_layout.addWidget(self.show_all_btn, 0, 0)
        
        self.show_critical_btn = QPushButton("🚨 Critical CVEs Only")
        self.show_critical_btn.clicked.connect(self.show_critical_cves)
        self.show_critical_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                font-weight: bold;
                padding: 8px;
                border-radius: 4px;
                border: none;
            }
            QPushButton:hover { background-color: #c0392b; }
        """)
        quick_id_layout.addWidget(self.show_critical_btn, 0, 1)
        
        self.show_recent_btn = QPushButton("🕒 Recent CVEs (30 days)")
        self.show_recent_btn.clicked.connect(self.show_recent_cves)
        self.show_recent_btn.setStyleSheet("""
            QPushButton {
                background-color: #f39c12;
                color: white;
                font-weight: bold;
                padding: 8px;
                border-radius: 4px;
                border: none;
            }
            QPushButton:hover { background-color: #e67e22; }
        """)
        quick_id_layout.addWidget(self.show_recent_btn, 0, 2)
        
        self.show_summary_btn = QPushButton("📊 CVE Summary")
        self.show_summary_btn.clicked.connect(self.show_cve_summary)
        self.show_summary_btn.setStyleSheet("""
            QPushButton {
                background-color: #9b59b6;
                color: white;
                font-weight: bold;
                padding: 8px;
                border-radius: 4px;
                border: none;
            }
            QPushButton:hover { background-color: #8e44ad; }
        """)
        quick_id_layout.addWidget(self.show_summary_btn, 0, 3)
        
        layout.addWidget(quick_id_group)
        
        # Search section
        search_group = QGroupBox("🔍 Advanced CVE Search & Analysis")
        search_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12px;
                border: 2px solid #9b59b6;
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
        search_layout = QGridLayout(search_group)
        
        # Search input
        search_layout.addWidget(QLabel("Search CVEs:"), 0, 0)
        self.cve_search_input = QLineEdit()
        self.cve_search_input.setPlaceholderText("Enter CVE ID, description, or keywords...")
        self.cve_search_input.returnPressed.connect(self.search_cves)
        search_layout.addWidget(self.cve_search_input, 0, 1)
        
        # Search button
        self.search_btn = QPushButton("🔍 Search")
        self.search_btn.setStyleSheet("""
            QPushButton {
                background-color: #9b59b6;
                color: white;
                border: none;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #8e44ad;
            }
        """)
        self.search_btn.clicked.connect(self.search_cves)
        search_layout.addWidget(self.search_btn, 0, 2)
        
        # Enhanced Filters
        search_layout.addWidget(QLabel("Severity:"), 1, 0)
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low"])
        self.severity_filter.currentTextChanged.connect(self.filter_cves)
        search_layout.addWidget(self.severity_filter, 1, 1)
        
        search_layout.addWidget(QLabel("Category:"), 1, 2)
        self.category_filter = QComboBox()
        self.category_filter.addItems(["All", "Web Application", "Network Service", "Operating System", "Cryptographic", "Other"])
        self.category_filter.currentTextChanged.connect(self.filter_cves)
        search_layout.addWidget(self.category_filter, 1, 3)
        
        search_layout.addWidget(QLabel("Vendor:"), 2, 0)
        self.vendor_filter = QComboBox()
        self.vendor_filter.addItems(["All"])
        self.vendor_filter.currentTextChanged.connect(self.filter_cves)
        search_layout.addWidget(self.vendor_filter, 2, 1)
        
        search_layout.addWidget(QLabel("Product:"), 2, 2)
        self.product_filter = QComboBox()
        self.product_filter.addItems(["All"])
        self.product_filter.currentTextChanged.connect(self.filter_cves)
        search_layout.addWidget(self.product_filter, 2, 3)
        
        search_layout.addWidget(QLabel("Min CVSS:"), 3, 0)
        self.cvss_filter = QSpinBox()
        self.cvss_filter.setRange(0, 10)
        self.cvss_filter.setValue(0)
        self.cvss_filter.valueChanged.connect(self.filter_cves)
        search_layout.addWidget(self.cvss_filter, 3, 1)
        
        layout.addWidget(search_group)
        
        # CVE results table
        results_group = QGroupBox("📊 CVE Search Results")
        results_layout = QVBoxLayout(results_group)
        
        self.cve_results_table = QTableWidget()
        self.cve_results_table.setColumnCount(9)
        self.cve_results_table.setHorizontalHeaderLabels([
            "CVE ID", "Severity", "CVSS Score", "Description", "Category", 
            "Vendor", "Product", "Published", "Exploit"
        ])
        self.cve_results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.cve_results_table.setMinimumHeight(300)
        self.cve_results_table.itemDoubleClicked.connect(self.show_cve_details)
        results_layout.addWidget(self.cve_results_table)
        
        # Results info
        self.cve_results_info = QLabel("Ready to identify CVEs...")
        self.cve_results_info.setStyleSheet("color: #7f8c8d; font-style: italic;")
        results_layout.addWidget(self.cve_results_info)
        
        layout.addWidget(results_group)
        
        # CVE details section
        details_group = QGroupBox("📋 CVE Details")
        details_layout = QVBoxLayout(details_group)
        
        self.cve_details_text = QTextEdit()
        self.cve_details_text.setMaximumHeight(200)
        self.cve_details_text.setPlaceholderText("Select a CVE to view detailed information...")
        details_layout.addWidget(self.cve_details_text)
        
        layout.addWidget(details_group)
        
        self.main_tabs.addTab(cve_tab, "🗄️ CVE Database")
    
    def create_training_modules_tab(self):
        """Create training modules tab"""
        training_tab = QWidget()
        layout = QVBoxLayout(training_tab)
        
        # Training modules list
        modules_group = QGroupBox("📚 Available Training Modules")
        modules_layout = QVBoxLayout(modules_group)
        
        self.modules_list = QListWidget()
        self.modules_list.setStyleSheet("""
            QListWidget {
                border: 2px solid #9b59b6;
                border-radius: 8px;
                background-color: white;
                font-size: 12px;
            }
            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid #e0e0e0;
            }
            QListWidget::item:selected {
                background-color: #9b59b6;
                color: white;
            }
            QListWidget::item:hover {
                background-color: #e8e8e8;
            }
        """)
        self.modules_list.itemClicked.connect(self.select_training_module)
        modules_layout.addWidget(self.modules_list)
        
        # Module details
        self.module_details_text = QTextEdit()
        self.module_details_text.setMaximumHeight(150)
        self.module_details_text.setPlaceholderText("Select a training module to view details...")
        modules_layout.addWidget(self.module_details_text)
        
        # Start module button
        self.start_module_btn = QPushButton("🚀 Start Training Module")
        self.start_module_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                padding: 12px 24px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
                min-width: 200px;
            }
            QPushButton:hover {
                background-color: #229954;
            }
            QPushButton:disabled {
                background-color: #95a5a6;
            }
        """)
        self.start_module_btn.setEnabled(False)
        self.start_module_btn.clicked.connect(self.start_training_module)
        modules_layout.addWidget(self.start_module_btn)
        
        layout.addWidget(modules_group)
        
        # Training content
        content_group = QGroupBox("📖 Training Content")
        content_layout = QVBoxLayout(content_group)
        
        self.training_content = QTextEdit()
        self.training_content.setPlaceholderText("Start a training module to view content...")
        content_layout.addWidget(self.training_content)
        
        layout.addWidget(content_group)
        
        self.main_tabs.addTab(training_tab, "📚 Training Modules")
    
    def create_quiz_system_tab(self):
        """Create quiz system tab"""
        quiz_tab = QWidget()
        layout = QVBoxLayout(quiz_tab)
        
        # Quiz selection
        quiz_selection_group = QGroupBox("🎯 Quiz Selection")
        quiz_selection_layout = QHBoxLayout(quiz_selection_group)
        
        quiz_selection_layout.addWidget(QLabel("Select Module:"))
        self.quiz_module_combo = QComboBox()
        self.quiz_module_combo.addItems(["cve_basics", "cvss_scoring", "critical_cves", "exploit_development"])
        quiz_selection_layout.addWidget(self.quiz_module_combo)
        
        self.start_quiz_btn = QPushButton("🎯 Start Quiz")
        self.start_quiz_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 10px 20px;
                font-size: 12px;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        self.start_quiz_btn.clicked.connect(self.start_quiz)
        quiz_selection_layout.addWidget(self.start_quiz_btn)
        
        layout.addWidget(quiz_selection_group)
        
        # Quiz content
        self.quiz_content_group = QGroupBox("❓ Quiz Questions")
        self.quiz_content_group.setVisible(False)
        quiz_content_layout = QVBoxLayout(self.quiz_content_group)
        
        self.quiz_question_label = QLabel()
        self.quiz_question_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #2c3e50;")
        self.quiz_question_label.setWordWrap(True)
        quiz_content_layout.addWidget(self.quiz_question_label)
        
        self.quiz_options_list = QListWidget()
        self.quiz_options_list.setStyleSheet("""
            QListWidget {
                border: 2px solid #9b59b6;
                border-radius: 8px;
                background-color: white;
                font-size: 12px;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #e0e0e0;
            }
            QListWidget::item:selected {
                background-color: #9b59b6;
                color: white;
            }
            QListWidget::item:hover {
                background-color: #e8e8e8;
            }
        """)
        self.quiz_options_list.itemClicked.connect(self.select_quiz_answer)
        quiz_content_layout.addWidget(self.quiz_options_list)
        
        # Quiz navigation
        quiz_nav_layout = QHBoxLayout()
        self.prev_question_btn = QPushButton("⬅️ Previous")
        self.prev_question_btn.setEnabled(False)
        self.prev_question_btn.clicked.connect(self.prev_question)
        quiz_nav_layout.addWidget(self.prev_question_btn)
        
        self.next_question_btn = QPushButton("Next ➡️")
        self.next_question_btn.setEnabled(False)
        self.next_question_btn.clicked.connect(self.next_question)
        quiz_nav_layout.addWidget(self.next_question_btn)
        
        self.submit_quiz_btn = QPushButton("✅ Submit Quiz")
        self.submit_quiz_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                padding: 10px 20px;
                font-size: 12px;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #229954;
            }
        """)
        self.submit_quiz_btn.setEnabled(False)
        self.submit_quiz_btn.clicked.connect(self.submit_quiz)
        quiz_nav_layout.addWidget(self.submit_quiz_btn)
        
        quiz_content_layout.addLayout(quiz_nav_layout)
        
        # Quiz progress
        self.quiz_progress = QProgressBar()
        self.quiz_progress.setVisible(False)
        quiz_content_layout.addWidget(self.quiz_progress)
        
        layout.addWidget(self.quiz_content_group)
        
        # Quiz results
        self.quiz_results_group = QGroupBox("📊 Quiz Results")
        self.quiz_results_group.setVisible(False)
        quiz_results_layout = QVBoxLayout(self.quiz_results_group)
        
        self.quiz_results_text = QTextEdit()
        self.quiz_results_text.setMaximumHeight(200)
        quiz_results_layout.addWidget(self.quiz_results_text)
        
        layout.addWidget(self.quiz_results_group)
        
        self.main_tabs.addTab(quiz_tab, "🎯 Quiz System")
    
    def create_progress_tracking_tab(self):
        """Create progress tracking tab"""
        progress_tab = QWidget()
        layout = QVBoxLayout(progress_tab)
        
        # Progress overview
        overview_group = QGroupBox("📈 Learning Progress Overview")
        overview_layout = QVBoxLayout(overview_group)
        
        self.progress_text = QTextEdit()
        self.progress_text.setMaximumHeight(200)
        self.progress_text.setPlaceholderText("Your learning progress will appear here...")
        overview_layout.addWidget(self.progress_text)
        
        # Refresh progress button
        self.refresh_progress_btn = QPushButton("🔄 Refresh Progress")
        self.refresh_progress_btn.setStyleSheet("""
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
        self.refresh_progress_btn.clicked.connect(self.refresh_progress)
        overview_layout.addWidget(self.refresh_progress_btn)
        
        layout.addWidget(overview_group)
        
        # CVE statistics
        stats_group = QGroupBox("📊 CVE Database Statistics")
        stats_layout = QVBoxLayout(stats_group)
        
        self.stats_text = QTextEdit()
        self.stats_text.setMaximumHeight(200)
        self.stats_text.setPlaceholderText("CVE database statistics will appear here...")
        stats_layout.addWidget(self.stats_text)
        
        # Refresh stats button
        self.refresh_stats_btn = QPushButton("📊 Refresh Statistics")
        self.refresh_stats_btn.setStyleSheet("""
            QPushButton {
                background-color: #9b59b6;
                color: white;
                border: none;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #8e44ad;
            }
        """)
        self.refresh_stats_btn.clicked.connect(self.refresh_statistics)
        stats_layout.addWidget(self.refresh_stats_btn)
        
        layout.addWidget(stats_group)
        
        self.main_tabs.addTab(progress_tab, "📈 Progress Tracking")
    
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
    
    def scroll_to_top(self):
        """Scroll to the top of the page"""
        try:
            if hasattr(self, 'main_scroll') and self.main_scroll:
                self.main_scroll.verticalScrollBar().setValue(0)
        except Exception as e:
            print(f"Scroll error: {e}")
    
    def scroll_to_bottom(self):
        """Scroll to the bottom of the page"""
        try:
            if hasattr(self, 'main_scroll') and self.main_scroll:
                scrollbar = self.main_scroll.verticalScrollBar()
                scrollbar.setValue(scrollbar.maximum())
        except Exception as e:
            print(f"Scroll error: {e}")
    
    def scroll_page_down(self):
        """Scroll down one page"""
        try:
            if hasattr(self, 'main_scroll') and self.main_scroll:
                scrollbar = self.main_scroll.verticalScrollBar()
                current_value = scrollbar.value()
                page_step = scrollbar.pageStep()
                scrollbar.setValue(current_value + page_step)
        except Exception as e:
            print(f"Scroll error: {e}")
    
    def scroll_page_up(self):
        """Scroll up one page"""
        try:
            if hasattr(self, 'main_scroll') and self.main_scroll:
                scrollbar = self.main_scroll.verticalScrollBar()
                current_value = scrollbar.value()
                page_step = scrollbar.pageStep()
                scrollbar.setValue(max(0, current_value - page_step))
        except Exception as e:
            print(f"Scroll error: {e}")
    
    def search_cves(self):
        """Search CVEs based on query and filters"""
        try:
            if not self.cve_trainer:
                QMessageBox.critical(self, "Error", "CVE trainer not initialized. Please restart the application.")
                return
            
            query = self.cve_search_input.text().strip()
            filters = {}
            
            severity = self.severity_filter.currentText()
            if severity != "All":
                filters['severity'] = severity
            
            min_cvss = self.cvss_filter.value()
            if min_cvss > 0:
                filters['min_cvss'] = min_cvss
            
            results = self.cve_trainer.search_cves(query, filters)
            
            # Populate results table
            self.cve_results_table.setRowCount(len(results))
            for row, cve in enumerate(results):
                self.cve_results_table.setItem(row, 0, QTableWidgetItem(cve.get('id', '')))
                self.cve_results_table.setItem(row, 1, QTableWidgetItem(cve.get('severity', '')))
                self.cve_results_table.setItem(row, 2, QTableWidgetItem(str(cve.get('cvss_score', 0))))
                self.cve_results_table.setItem(row, 3, QTableWidgetItem(cve.get('description', '')[:100] + '...'))
                self.cve_results_table.setItem(row, 4, QTableWidgetItem(cve.get('category', '')))
                self.cve_results_table.setItem(row, 5, QTableWidgetItem(cve.get('published_date', '')))
            
        except Exception as e:
            self.cve_details_text.setText(f"Error searching CVEs: {str(e)}")
    
    def show_cve_details(self, item):
        """Show detailed CVE information"""
        try:
            if not self.cve_trainer:
                QMessageBox.critical(self, "Error", "CVE trainer not initialized. Please restart the application.")
                return
                
            row = item.row()
            cve_id = self.cve_results_table.item(row, 0).text()
            
            cve_info = self.cve_trainer.get_cve_info(cve_id)
            
            if cve_info:
                details = f"""
🔍 CVE ID: {cve_info.get('id', 'N/A')}
📊 Severity: {cve_info.get('severity', 'N/A')}
🎯 CVSS Score: {cve_info.get('cvss_score', 'N/A')}
📅 Published: {cve_info.get('published_date', 'N/A')}
🏷️ Category: {cve_info.get('category', 'N/A')}

📝 Description:
{cve_info.get('description', 'No description available')}

🏢 Products: {', '.join(cve_info.get('products', []))}
🏭 Vendors: {', '.join(cve_info.get('vendors', []))}
🏷️ Tags: {', '.join(cve_info.get('tags', []))}

🔧 Attack Vector: {cve_info.get('attack_vector', 'N/A')}
⚡ Attack Complexity: {cve_info.get('attack_complexity', 'N/A')}
🔐 Privileges Required: {cve_info.get('privileges_required', 'N/A')}
👤 User Interaction: {cve_info.get('user_interaction', 'N/A')}

📊 Impact:
• Confidentiality: {cve_info.get('confidentiality_impact', 'N/A')}
• Integrity: {cve_info.get('integrity_impact', 'N/A')}
• Availability: {cve_info.get('availability_impact', 'N/A')}
                """
                self.cve_details_text.setText(details)
            else:
                self.cve_details_text.setText("CVE information not found.")
                
        except Exception as e:
            self.cve_details_text.setText(f"Error loading CVE details: {str(e)}")
    
    def show_all_cves(self):
        """Show all CVEs in the database"""
        try:
            if not self.cve_trainer:
                QMessageBox.critical(self, "Error", "CVE trainer not initialized. Please restart the application.")
                return
            all_cves = self.cve_trainer.get_all_cves()
            self.display_cve_results(all_cves)
            self.cve_results_info.setText(f"📋 Showing all {len(all_cves)} CVEs in database")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error loading all CVEs: {str(e)}")
    
    def show_critical_cves(self):
        """Show only critical CVEs"""
        try:
            if not self.cve_trainer:
                QMessageBox.critical(self, "Error", "CVE trainer not initialized. Please restart the application.")
                return
            critical_cves = self.cve_trainer.get_critical_cves()
            self.display_cve_results(critical_cves)
            self.cve_results_info.setText(f"🚨 Showing {len(critical_cves)} critical CVEs (CVSS >= 9.0)")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error loading critical CVEs: {str(e)}")
    
    def show_recent_cves(self):
        """Show recent CVEs (last 30 days)"""
        try:
            if not self.cve_trainer:
                QMessageBox.critical(self, "Error", "CVE trainer not initialized. Please restart the application.")
                return
            recent_cves = self.cve_trainer.get_recent_cves(30)
            self.display_cve_results(recent_cves)
            self.cve_results_info.setText(f"🕒 Showing {len(recent_cves)} CVEs published in the last 30 days")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error loading recent CVEs: {str(e)}")
    
    def show_cve_summary(self):
        """Show comprehensive CVE summary"""
        try:
            if not self.cve_trainer:
                QMessageBox.critical(self, "Error", "CVE trainer not initialized. Please restart the application.")
                return
            summary = self.cve_trainer.get_cve_summary()
            if "error" in summary:
                QMessageBox.critical(self, "Error", f"Error getting CVE summary: {summary['error']}")
                return
            
            # Create summary dialog
            summary_dialog = QMessageBox(self)
            summary_dialog.setWindowTitle("📊 CVE Database Summary")
            summary_dialog.setIcon(QMessageBox.Information)
            
            summary_text = f"""
            <h3>📊 CVE Database Summary</h3>
            <p><b>Total CVEs:</b> {summary['total_cves']}</p>
            <p><b>Critical CVEs:</b> {summary['critical_cves_count']}</p>
            <p><b>Recent CVEs (30 days):</b> {summary['recent_cves_count']}</p>
            
            <h4>📈 Severity Breakdown:</h4>
            <ul>
            """
            for severity in summary['severities']:
                summary_text += f"<li>{severity}</li>"
            summary_text += "</ul>"
            
            summary_text += f"""
            <h4>🏷️ Categories:</h4>
            <ul>
            """
            for category in summary['categories']:
                summary_text += f"<li>{category}</li>"
            summary_text += "</ul>"
            
            summary_text += f"""
            <h4>🏢 Top Vendors:</h4>
            <ul>
            """
            for vendor in summary['vendors'][:10]:  # Show top 10
                summary_text += f"<li>{vendor}</li>"
            summary_text += "</ul>"
            
            summary_text += f"""
            <h4>🔝 Top CVEs by CVSS Score:</h4>
            <ul>
            """
            for cve in summary['top_cves'][:5]:  # Show top 5
                summary_text += f"<li>{cve['id']} - CVSS: {cve['cvss_score']} ({cve['severity']})</li>"
            summary_text += "</ul>"
            
            summary_dialog.setText(summary_text)
            summary_dialog.exec_()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error getting CVE summary: {str(e)}")
    
    def filter_cves(self):
        """Filter CVEs based on current filter settings"""
        try:
            if not self.cve_trainer:
                QMessageBox.critical(self, "Error", "CVE trainer not initialized. Please restart the application.")
                return
            
            # Get filter values
            severity = self.severity_filter.currentText()
            category = self.category_filter.currentText()
            vendor = self.vendor_filter.currentText()
            product = self.product_filter.currentText()
            min_cvss = self.cvss_filter.value()
            
            # Get all CVEs
            all_cves = self.cve_trainer.get_all_cves()
            filtered_cves = []
            
            for cve in all_cves:
                # Apply filters
                if severity != "All" and cve['severity'] != severity:
                    continue
                if category != "All" and cve['category'] != category:
                    continue
                if vendor != "All" and vendor not in cve['vendors']:
                    continue
                if product != "All" and product not in cve['products']:
                    continue
                if min_cvss > 0 and cve['cvss_score'] < min_cvss:
                    continue
                
                filtered_cves.append(cve)
            
            self.display_cve_results(filtered_cves)
            self.cve_results_info.setText(f"🔍 Showing {len(filtered_cves)} CVEs matching current filters")
            
        except Exception as e:
            QMessageBox.critical(self, "Filter Error", f"Error filtering CVEs: {str(e)}")
    
    def load_filter_options(self):
        """Load vendor and product options for filters"""
        try:
            if not self.cve_trainer:
                print("CVE trainer not initialized, skipping filter options loading")
                return
            summary = self.cve_trainer.get_cve_summary()
            if "error" not in summary:
                # Update vendor filter
                self.vendor_filter.clear()
                self.vendor_filter.addItem("All")
                for vendor in sorted(summary['vendors']):
                    self.vendor_filter.addItem(vendor)
                
                # Update product filter
                self.product_filter.clear()
                self.product_filter.addItem("All")
                for product in sorted(summary['products']):
                    self.product_filter.addItem(product)
                    
        except Exception as e:
            print(f"Error loading filter options: {e}")
    
    def display_cve_results(self, cves):
        """Display CVE results in the table"""
        try:
            self.cve_results_table.setRowCount(len(cves))
            
            for row, cve in enumerate(cves):
                # CVE ID
                self.cve_results_table.setItem(row, 0, QTableWidgetItem(cve.get('id', '')))
                
                # Severity with color coding
                severity_item = QTableWidgetItem(cve.get('severity', ''))
                if cve.get('severity') == 'Critical':
                    severity_item.setForeground(QColor('red'))
                elif cve.get('severity') == 'High':
                    severity_item.setForeground(QColor('orange'))
                elif cve.get('severity') == 'Medium':
                    severity_item.setForeground(QColor('gold'))
                self.cve_results_table.setItem(row, 1, severity_item)
                
                # CVSS Score
                self.cve_results_table.setItem(row, 2, QTableWidgetItem(str(cve.get('cvss_score', 0))))
                
                # Description (truncated)
                description = cve.get('description', '')
                if len(description) > 100:
                    description = description[:100] + '...'
                self.cve_results_table.setItem(row, 3, QTableWidgetItem(description))
                
                # Category
                self.cve_results_table.setItem(row, 4, QTableWidgetItem(cve.get('category', '')))
                
                # Vendor
                vendors = cve.get('vendors', [])
                vendor_text = ', '.join(vendors[:2]) if vendors else ''
                if len(vendors) > 2:
                    vendor_text += f' (+{len(vendors)-2} more)'
                self.cve_results_table.setItem(row, 5, QTableWidgetItem(vendor_text))
                
                # Product
                products = cve.get('products', [])
                product_text = ', '.join(products[:2]) if products else ''
                if len(products) > 2:
                    product_text += f' (+{len(products)-2} more)'
                self.cve_results_table.setItem(row, 6, QTableWidgetItem(product_text))
                
                # Published Date
                self.cve_results_table.setItem(row, 7, QTableWidgetItem(cve.get('published_date', '')))
                
                # Exploit Available
                exploit_item = QTableWidgetItem("Yes" if cve.get('exploit_available', False) else "No")
                if cve.get('exploit_available', False):
                    exploit_item.setForeground(QColor('darkgreen'))
                else:
                    exploit_item.setForeground(QColor('darkred'))
                self.cve_results_table.setItem(row, 8, exploit_item)
                
        except Exception as e:
            QMessageBox.critical(self, "Display Error", f"Error displaying CVE results: {str(e)}")
    
    def select_training_module(self, item):
        """Select a training module"""
        try:
            module_id = item.text().split(' - ')[0].lower().replace(' ', '_')
            
            from core.cve_trainer import CVETrainer
            trainer = CVETrainer()
            modules = trainer.get_training_modules()
            
            if module_id in modules:
                module = modules[module_id]
                details = f"""
📚 {module['title']}
📝 {module['description']}
⏱️ Duration: {module['duration']}
🎯 Difficulty: {module['difficulty']}

📋 Topics Covered:
{chr(10).join('• ' + topic for topic in module['topics'])}

📖 Lessons:
{chr(10).join('• ' + lesson['title'] for lesson in module['lessons'])}
                """
                self.module_details_text.setText(details)
                self.current_module = module_id
                self.start_module_btn.setEnabled(True)
            else:
                self.module_details_text.setText("Module details not found.")
                self.start_module_btn.setEnabled(False)
                
        except Exception as e:
            self.module_details_text.setText(f"Error loading module details: {str(e)}")
    
    def start_training_module(self):
        """Start the selected training module"""
        try:
            if not self.current_module:
                return
            
            from core.cve_trainer import CVETrainer
            trainer = CVETrainer()
            modules = trainer.get_training_modules()
            
            if self.current_module in modules:
                module = modules[self.current_module]
                content = f"""
🚀 Starting Training Module: {module['title']}

{module['description']}

📚 Module Content:

{chr(10).join(f"📖 {lesson['title']}:{chr(10)}{lesson['content']}{chr(10)}" for lesson in module['lessons'])}

🎯 Next Steps:
1. Review the content above
2. Go to the Quiz System tab
3. Take the quiz for this module
4. Track your progress

Good luck with your CVE training!
                """
                self.training_content.setText(content)
                self.main_tabs.setCurrentIndex(1)  # Switch to training modules tab
                
        except Exception as e:
            self.training_content.setText(f"Error starting training module: {str(e)}")
    
    def start_quiz(self):
        """Start a quiz for the selected module"""
        try:
            module_id = self.quiz_module_combo.currentText()
            
            from core.cve_trainer import CVETrainer
            trainer = CVETrainer()
            questions = trainer.get_quiz_questions(module_id)
            
            if questions:
                self.current_quiz = questions
                self.quiz_answers = [-1] * len(questions)
                self.current_question = 0
                
                self.quiz_content_group.setVisible(True)
                self.quiz_progress.setVisible(True)
                self.quiz_progress.setMaximum(len(questions))
                self.quiz_progress.setValue(0)
                
                self.show_question(0)
            else:
                self.quiz_question_label.setText("No questions available for this module.")
                
        except Exception as e:
            self.quiz_question_label.setText(f"Error starting quiz: {str(e)}")
    
    def show_question(self, question_index):
        """Show a specific quiz question"""
        try:
            if not self.current_quiz or question_index >= len(self.current_quiz):
                return
            
            question = self.current_quiz[question_index]
            self.quiz_question_label.setText(f"Question {question_index + 1}: {question['question']}")
            
            # Populate options
            self.quiz_options_list.clear()
            for i, option in enumerate(question['options']):
                item = QListWidgetItem(f"{chr(65 + i)}. {option}")
                item.setData(Qt.UserRole, i)
                self.quiz_options_list.addItem(item)
            
            # Update navigation buttons
            self.prev_question_btn.setEnabled(question_index > 0)
            self.next_question_btn.setEnabled(question_index < len(self.current_quiz) - 1)
            self.submit_quiz_btn.setEnabled(question_index == len(self.current_quiz) - 1)
            
            # Update progress
            self.quiz_progress.setValue(question_index + 1)
            
        except Exception as e:
            self.quiz_question_label.setText(f"Error showing question: {str(e)}")
    
    def select_quiz_answer(self, item):
        """Select an answer for the current quiz question"""
        try:
            answer_index = item.data(Qt.UserRole)
            self.quiz_answers[self.current_question] = answer_index
            
            # Visual feedback
            for i in range(self.quiz_options_list.count()):
                self.quiz_options_list.item(i).setBackground(Qt.white)
            item.setBackground(Qt.lightGray)
            
        except Exception as e:
            print(f"Error selecting answer: {e}")
    
    def prev_question(self):
        """Go to previous question"""
        if self.current_question > 0:
            self.current_question -= 1
            self.show_question(self.current_question)
    
    def next_question(self):
        """Go to next question"""
        if self.current_question < len(self.current_quiz) - 1:
            self.current_question += 1
            self.show_question(self.current_question)
    
    def submit_quiz(self):
        """Submit the quiz and show results"""
        try:
            if not self.current_quiz:
                return
            
            # Check if all questions are answered
            if -1 in self.quiz_answers:
                self.quiz_results_text.setText("Please answer all questions before submitting.")
                return
            
            from core.cve_trainer import CVETrainer
            trainer = CVETrainer()
            module_id = self.quiz_module_combo.currentText()
            
            results = trainer.submit_quiz(module_id, self.quiz_answers)
            
            # Display results
            result_text = f"""
🎯 Quiz Results for {module_id.replace('_', ' ').title()}

📊 Score: {results['score']:.1f}%
✅ Correct Answers: {results['correct_answers']}/{results['total_questions']}
{'🎉 PASSED!' if results['passed'] else '❌ FAILED'}

📋 Detailed Results:
{chr(10).join(f"Q{i+1}: {'✅' if result['is_correct'] else '❌'} {result['explanation']}" for i, result in enumerate(results['results']))}

{'🎊 Congratulations! You passed the quiz!' if results['passed'] else '📚 Review the material and try again!'}
            """
            
            self.quiz_results_text.setText(result_text)
            self.quiz_results_group.setVisible(True)
            
        except Exception as e:
            self.quiz_results_text.setText(f"Error submitting quiz: {str(e)}")
    
    def refresh_progress(self):
        """Refresh user progress"""
        try:
            from core.cve_trainer import CVETrainer
            trainer = CVETrainer()
            progress = trainer.get_user_progress()
            
            progress_text = f"""
📈 Your Learning Progress

👤 User: {progress.get('user_id', 'default')}
📚 Modules Completed: {progress.get('total_modules_completed', 0)}
📊 Average Quiz Score: {progress.get('average_quiz_score', 0):.1f}%

📋 Recent Quiz Results:
{chr(10).join(f"• {result[1]}: {result[2]:.1f}% ({result[0]})" for result in progress.get('quiz_results', [])[:5])}

🎯 Training Progress:
{chr(10).join(f"• {progress[0]}: {progress[2]:.1f}% (Attempts: {progress[3]})" for progress in progress.get('training_progress', []))}
            """
            
            self.progress_text.setText(progress_text)
            
        except Exception as e:
            self.progress_text.setText(f"Error loading progress: {str(e)}")
    
    def refresh_statistics(self):
        """Refresh CVE database statistics"""
        try:
            from core.cve_trainer import CVETrainer
            trainer = CVETrainer()
            stats = trainer.get_cve_statistics()
            
            stats_text = f"""
📊 CVE Database Statistics

📈 Total CVEs: {stats.get('total_cves', 0)}
📅 Last Updated: {stats.get('database_last_updated', 'N/A')}

🎯 Severity Breakdown:
{chr(10).join(f"• {severity}: {count}" for severity, count in stats.get('severity_breakdown', {}).items())}

📂 Category Breakdown:
{chr(10).join(f"• {category}: {count}" for category, count in stats.get('category_breakdown', {}).items())}

📊 Average CVSS Score: {stats.get('average_cvss_score', 0)}
            """
            
            self.stats_text.setText(stats_text)
            
        except Exception as e:
            self.stats_text.setText(f"Error loading statistics: {str(e)}")
