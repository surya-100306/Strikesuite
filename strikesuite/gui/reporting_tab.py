#!/usr/bin/env python3
"""
Reporting Tab
GUI for report generation functionality
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QLineEdit, QPushButton, QTextEdit,
                             QCheckBox, QGroupBox, QTableWidget, QTableWidgetItem,
                             QHeaderView, QComboBox, QFileDialog, QProgressBar,
                             QScrollArea, QSplitter, QTabWidget, QFrame,
                             QSpinBox, QDateEdit, QSlider, QDial, QListWidget,
                             QListWidgetItem, QTreeWidget, QTreeWidgetItem,
                             QCalendarWidget, QTimeEdit, QDoubleSpinBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QDate, QTime, QTimer
from PyQt5.QtGui import QFont, QPixmap, QIcon, QPalette, QColor
import os
import datetime
import json
import sys
from pathlib import Path

# Import core modules
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

try:
    from core.reporter import ReportGenerator
    from utils.db_utils import get_scan_history, get_vulnerability_data
except ImportError as e:
    print(f"Warning: Could not import some modules: {e}")

class ReportingTab(QWidget):
    """Report generation tab widget"""
    
    def __init__(self):
        super().__init__()
        self.scroll_area = None
        self.is_fullscreen = False
        self.original_geometry = None
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface with modern design and full scroll support"""
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
        main_widget_layout = QVBoxLayout(main_widget)
        main_widget_layout.setSpacing(15)
        main_widget_layout.setContentsMargins(15, 15, 15, 15)
        
        # Add welcome section
        self.create_welcome_section(main_widget_layout)
        
        # Set the main widget in scroll area
        self.scroll_area.setWidget(main_widget)
        
        # Set main layout for the tab
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(self.scroll_area)
        
        # Add all sections to the main widget layout
        self.create_report_configuration_section(main_widget_layout)
        self.create_scan_history_section(main_widget_layout)
        self.create_report_options_section(main_widget_layout)
        self.create_generation_section(main_widget_layout)
        self.create_status_section(main_widget_layout)
    
    def create_report_configuration_section(self, layout):
        """Create report configuration section with improved UI"""
        config_group = QGroupBox("📊 Report Configuration")
        config_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                border: 2px solid #8e44ad;
                border-radius: 10px;
                margin-top: 15px;
                padding-top: 20px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f8f9fa, stop:1 #e9ecef);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px 0 10px;
                color: #8e44ad;
                font-size: 16px;
            }
        """)
        config_layout = QGridLayout(config_group)
        config_layout.setSpacing(15)
        
        # Report title with improved styling
        title_label = QLabel("📝 Report Title:")
        title_label.setStyleSheet("""
            QLabel {
                font-weight: bold;
                color: #2c3e50;
                font-size: 12px;
            }
        """)
        config_layout.addWidget(title_label, 0, 0)
        
        self.title_input = QLineEdit()
        self.title_input.setText("Security Assessment Report")
        self.title_input.setPlaceholderText("Enter a descriptive title for your report...")
        self.title_input.setStyleSheet("""
            QLineEdit {
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 8px;
                background-color: white;
                font-size: 12px;
                min-height: 20px;
            }
            QLineEdit:focus {
                border-color: #8e44ad;
                background-color: #f8f9fa;
            }
            QLineEdit:hover {
                border-color: #95a5a6;
            }
        """)
        config_layout.addWidget(self.title_input, 0, 1)
        
        # Report format with improved styling
        format_label = QLabel("📄 Format:")
        format_label.setStyleSheet("""
            QLabel {
                font-weight: bold;
                color: #2c3e50;
                font-size: 12px;
            }
        """)
        config_layout.addWidget(format_label, 1, 0)
        
        self.format_combo = QComboBox()
        self.format_combo.addItems(["PDF", "HTML", "JSON", "XML", "CSV"])
        self.format_combo.setCurrentText("PDF")
        self.format_combo.setStyleSheet("""
            QComboBox {
                padding: 12px;
                border: 2px solid #bdc3c7;
                border-radius: 8px;
                background-color: white;
                font-size: 12px;
                min-height: 20px;
            }
            QComboBox:focus {
                border-color: #8e44ad;
                background-color: #f8f9fa;
            }
            QComboBox:hover {
                border-color: #95a5a6;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            QComboBox::down-arrow {
                image: none;
                border: none;
            }
        """)
        config_layout.addWidget(self.format_combo, 1, 1)
        
        # Include sections with improved styling
        sections_label = QLabel("📋 Include Sections:")
        sections_label.setStyleSheet("""
            QLabel {
                font-weight: bold;
                color: #2c3e50;
                font-size: 12px;
            }
        """)
        config_layout.addWidget(sections_label, 2, 0)
        
        sections_layout = QHBoxLayout()
        sections_layout.setSpacing(10)
        
        self.include_executive = QCheckBox("Executive Summary")
        self.include_executive.setChecked(True)
        self.include_vulnerabilities = QCheckBox("Vulnerabilities")
        self.include_vulnerabilities.setChecked(True)
        self.include_recommendations = QCheckBox("Recommendations")
        self.include_recommendations.setChecked(True)
        self.include_appendix = QCheckBox("Appendix")
        self.include_appendix.setChecked(False)
        
        sections_layout.addWidget(self.include_executive)
        sections_layout.addWidget(self.include_vulnerabilities)
        sections_layout.addWidget(self.include_recommendations)
        sections_layout.addWidget(self.include_appendix)
        
        config_layout.addLayout(sections_layout, 2, 1)
        
        layout.addWidget(config_group)
    
    def create_scan_history_section(self, layout):
        """Create scan history section with improved UI"""
        # Data source selection
        data_group = QGroupBox("📋 Data Source")
        data_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                border: 2px solid #27ae60;
                border-radius: 10px;
                margin-top: 15px;
                padding-top: 20px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f8f9fa, stop:1 #e9ecef);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px 0 10px;
                color: #27ae60;
                font-size: 16px;
            }
        """)
        data_layout = QVBoxLayout(data_group)
        
        # Enhanced scan history selection with more columns and larger size
        self.scan_history_table = QTableWidget()
        self.scan_history_table.setColumnCount(8)
        self.scan_history_table.setHorizontalHeaderLabels([
            "Date", "Target", "Type", "Status", "Vulnerabilities", "Duration", "Risk Score", "Details"
        ])
        
        # Set column widths for better information display
        header = self.scan_history_table.horizontalHeader()
        header.setStretchLastSection(True)
        header.resizeSection(0, 120)  # Date
        header.resizeSection(1, 150)   # Target
        header.resizeSection(2, 100)  # Type
        header.resizeSection(3, 80)   # Status
        header.resizeSection(4, 100)  # Vulnerabilities
        header.resizeSection(5, 80)   # Duration
        header.resizeSection(6, 80)    # Risk Score
        header.resizeSection(7, 200)  # Details
        
        # Set table properties
        self.scan_history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.scan_history_table.setAlternatingRowColors(True)
        self.scan_history_table.setSortingEnabled(True)
        self.scan_history_table.setMinimumHeight(300)
        self.scan_history_table.setMaximumHeight(500)
        
        # Enhanced styling
        self.scan_history_table.setStyleSheet("""
            QTableWidget {
                border: 2px solid #ddd;
                border-radius: 8px;
                background: white;
                gridline-color: #e0e0e0;
                font-size: 11px;
            }
            QTableWidget::item {
                padding: 10px 8px;
                border-bottom: 1px solid #f0f0f0;
            }
            QTableWidget::item:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #8e44ad, stop:1 #9b59b6);
                color: white;
            }
            QTableWidget::item:hover {
                background: #f8f9fa;
            }
            QHeaderView::section {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f8f9fa, stop:1 #e9ecef);
                padding: 8px;
                border: 1px solid #ddd;
                font-weight: bold;
                color: #333;
            }
        """)
        data_layout.addWidget(self.scan_history_table)
        
        # Load scan history
        self.load_scan_history()
        
        # Connect table selection to show detailed info
        self.scan_history_table.itemSelectionChanged.connect(self.on_table_selection_changed)
        
        layout.addWidget(data_group)
        
        # Add detailed information display section
        self.create_detailed_info_section(layout)
        
        # Add professional report generator section
        self.create_professional_report_section(layout)
        
        # Report generation controls
        controls_group = QGroupBox("⚙️ Report Generation")
        controls_group.setStyleSheet("""
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
                left: 10px;
                padding: 0 5px 0 5px;
                color: #e74c3c;
            }
        """)
        controls_layout = QHBoxLayout(controls_group)
        
        # Generate button
        self.generate_btn = QPushButton("🚀 Generate Report")
        self.generate_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #8e44ad, stop:1 #9b59b6);
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #9b59b6, stop:1 #8e44ad);
            }
            QPushButton:pressed {
                background: #7d3c98;
            }
        """)
        self.generate_btn.clicked.connect(self.generate_report)
        controls_layout.addWidget(self.generate_btn)
        
        # Preview button
        self.preview_btn = QPushButton("👁️ Preview")
        self.preview_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #3498db, stop:1 #2980b9);
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #2980b9, stop:1 #3498db);
            }
            QPushButton:pressed {
                background: #21618c;
            }
        """)
        self.preview_btn.clicked.connect(self.preview_report)
        controls_layout.addWidget(self.preview_btn)
        
        # Export button
        self.export_btn = QPushButton("💾 Export")
        self.export_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #27ae60, stop:1 #2ecc71);
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #2ecc71, stop:1 #27ae60);
            }
            QPushButton:pressed {
                background: #1e8449;
            }
        """)
        self.export_btn.clicked.connect(self.export_report)
        controls_layout.addWidget(self.export_btn)
        
        layout.addWidget(controls_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #ddd;
                border-radius: 5px;
                text-align: center;
                background: #f8f9fa;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #8e44ad, stop:1 #9b59b6);
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Status display
        self.status_label = QLabel("Ready to generate reports")
        self.status_label.setStyleSheet("""
            QLabel {
                color: #27ae60;
                font-weight: bold;
                padding: 8px;
                background: #d5f4e6;
                border: 1px solid #27ae60;
                border-radius: 4px;
            }
        """)
        layout.addWidget(self.status_label)
    
    def toggle_fullscreen(self):
        """Toggle full screen mode for reporting tab"""
        try:
            if not self.is_fullscreen:
                # Enter full screen
                self.original_geometry = self.geometry()
                self.showFullScreen()
                self.is_fullscreen = True
                print("🖥️ Reporting tab full screen mode activated")
            else:
                # Exit full screen
                self.showNormal()
                if self.original_geometry:
                    self.setGeometry(self.original_geometry)
                self.is_fullscreen = False
                print("🖥️ Reporting tab full screen mode deactivated")
                
        except Exception as e:
            print(f"❌ Full screen toggle failed: {str(e)}")
    
    def scroll_down(self):
        """Scroll down in the reporting tab"""
        try:
            if self.scroll_area:
                scrollbar = self.scroll_area.verticalScrollBar()
                if scrollbar:
                    scrollbar.setValue(scrollbar.value() + 50)
                    print("⬇️ Scrolled down in reporting tab")
                    return
            print("⚠️ No scrollable content found in reporting tab")
                
        except Exception as e:
            print(f"❌ Scroll down failed: {str(e)}")
    
    def scroll_up(self):
        """Scroll up in the reporting tab"""
        try:
            if self.scroll_area:
                scrollbar = self.scroll_area.verticalScrollBar()
                if scrollbar:
                    scrollbar.setValue(max(0, scrollbar.value() - 50))
                    print("⬆️ Scrolled up in reporting tab")
                    return
            print("⚠️ No scrollable content found in reporting tab")
                
        except Exception as e:
            print(f"❌ Scroll up failed: {str(e)}")
    
    def scroll_to_top(self):
        """Scroll to the top of the reporting tab"""
        try:
            if self.scroll_area:
                scrollbar = self.scroll_area.verticalScrollBar()
                if scrollbar:
                    scrollbar.setValue(0)
                    print("⬆️ Scrolled to top of reporting tab")
                    return
            print("⚠️ No scrollable content found in reporting tab")
                
        except Exception as e:
            print(f"❌ Scroll to top failed: {str(e)}")
    
    def scroll_to_bottom(self):
        """Scroll to the bottom of the reporting tab"""
        try:
            if self.scroll_area:
                scrollbar = self.scroll_area.verticalScrollBar()
                if scrollbar:
                    scrollbar.setValue(scrollbar.maximum())
                    print("⬇️ Scrolled to bottom of reporting tab")
                    return
            print("⚠️ No scrollable content found in reporting tab")
                
        except Exception as e:
            print(f"❌ Scroll to bottom failed: {str(e)}")
    
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
            elif event.key() == Qt.Key_Home:
                self.scroll_to_top()
            elif event.key() == Qt.Key_End:
                self.scroll_to_bottom()
        else:
            super().keyPressEvent(event)
    
    def create_report_options_section(self, layout):
        """Create report options section with improved UI"""
        options_group = QGroupBox("⚙️ Report Options")
        options_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                border: 2px solid #e67e22;
                border-radius: 10px;
                margin-top: 15px;
                padding-top: 20px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f8f9fa, stop:1 #e9ecef);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px 0 10px;
                color: #e67e22;
                font-size: 16px;
            }
        """)
        options_layout = QGridLayout(options_group)
        options_layout.setSpacing(15)
        
        # Add options here
        layout.addWidget(options_group)
    
    def create_generation_section(self, layout):
        """Create report generation section with improved UI"""
        generation_group = QGroupBox("🚀 Generate Report")
        generation_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                border: 2px solid #9b59b6;
                border-radius: 10px;
                margin-top: 15px;
                padding-top: 20px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f8f9fa, stop:1 #e9ecef);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px 0 10px;
                color: #9b59b6;
                font-size: 16px;
            }
        """)
        generation_layout = QVBoxLayout(generation_group)
        
        # Generate button with improved styling
        self.generate_btn = QPushButton("🚀 Generate Report")
        self.generate_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #9b59b6, stop:1 #8e44ad);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 15px 30px;
                font-size: 14px;
                font-weight: bold;
                min-height: 20px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #8e44ad, stop:1 #7d3c98);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #7d3c98, stop:1 #6c3483);
            }
        """)
        self.generate_btn.clicked.connect(self.generate_report)
        generation_layout.addWidget(self.generate_btn)
        
        layout.addWidget(generation_group)
    
    def create_status_section(self, layout):
        """Create status section with improved UI"""
        status_group = QGroupBox("📊 Status")
        status_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                border: 2px solid #3498db;
                border-radius: 10px;
                margin-top: 15px;
                padding-top: 20px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f8f9fa, stop:1 #e9ecef);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px 0 10px;
                color: #3498db;
                font-size: 16px;
            }
        """)
        status_layout = QVBoxLayout(status_group)
        
        # Status label with improved styling
        self.status_label = QLabel("Ready to generate report")
        self.status_label.setStyleSheet("""
            QLabel {
                padding: 15px;
                background: #d5f4e6;
                border: 1px solid #27ae60;
                border-radius: 4px;
            }
        """)
        status_layout.addWidget(self.status_label)
        
        layout.addWidget(status_group)
    
    def generate_report(self):
        """Generate report with improved user feedback"""
        try:
            # Update status
            self.status_label.setText("🔄 Generating report...")
            self.status_label.setStyleSheet("""
                QLabel {
                    padding: 15px;
                    background: #fff3cd;
                    border: 1px solid #ffc107;
                    border-radius: 4px;
                    color: #856404;
                }
            """)
            
            # Get report configuration
            title = self.title_input.text() or "Security Assessment Report"
            format_type = self.format_combo.currentText()
            
            # Get selected sections
            sections = []
            if self.include_executive.isChecked():
                sections.append("Executive Summary")
            if self.include_vulnerabilities.isChecked():
                sections.append("Vulnerabilities")
            if self.include_recommendations.isChecked():
                sections.append("Recommendations")
            if self.include_appendix.isChecked():
                sections.append("Appendix")
            
            # Simulate report generation
            import time
            time.sleep(1)  # Simulate processing time
            
            # Update status with success
            self.status_label.setText(f"✅ Report generated successfully: {title}.{format_type.lower()}")
            self.status_label.setStyleSheet("""
                QLabel {
                    padding: 15px;
                    background: #d5f4e6;
                    border: 1px solid #27ae60;
                    border-radius: 4px;
                    color: #155724;
                }
            """)
            
            print(f"📊 Report generated: {title} ({format_type})")
            print(f"📋 Sections included: {', '.join(sections)}")
            
        except Exception as e:
            # Update status with error
            self.status_label.setText(f"❌ Error generating report: {str(e)}")
            self.status_label.setStyleSheet("""
                QLabel {
                    padding: 15px;
                    background: #f8d7da;
                    border: 1px solid #dc3545;
                    border-radius: 4px;
                    color: #721c24;
                }
            """)
            print(f"❌ Report generation failed: {str(e)}")
        
    def create_welcome_section(self, layout):
        """Create welcome section with project info"""
        welcome_frame = QFrame()
        welcome_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #8e44ad, stop:1 #9b59b6);
                border-radius: 10px;
                padding: 20px;
            }
        """)
        welcome_layout = QVBoxLayout(welcome_frame)
        
        title_label = QLabel("📊 StrikeSuite Report Generator")
        title_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 24px;
                font-weight: bold;
                padding: 10px;
            }
        """)
        welcome_layout.addWidget(title_label)
        
        desc_label = QLabel("Generate comprehensive security assessment reports with professional formatting")
        desc_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 14px;
                padding: 5px 10px;
            }
        """)
        welcome_layout.addWidget(desc_label)
        
        # Add full screen and scroll controls
        controls_layout = QHBoxLayout()
        
        fullscreen_btn = QPushButton("🖥️ Full Screen (F11)")
        fullscreen_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 255, 255, 0.2);
                color: white;
                border: 1px solid rgba(255, 255, 255, 0.3);
                border-radius: 5px;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 0.3);
            }
        """)
        fullscreen_btn.clicked.connect(self.toggle_fullscreen)
        controls_layout.addWidget(fullscreen_btn)
        
        scroll_down_btn = QPushButton("⬇️ Scroll Down (Ctrl+Down)")
        scroll_down_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 255, 255, 0.2);
                color: white;
                border: 1px solid rgba(255, 255, 255, 0.3);
                border-radius: 5px;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 0.3);
            }
        """)
        scroll_down_btn.clicked.connect(self.scroll_down)
        controls_layout.addWidget(scroll_down_btn)
        
        scroll_up_btn = QPushButton("⬆️ Scroll Up (Ctrl+Up)")
        scroll_up_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 255, 255, 0.2);
                color: white;
                border: 1px solid rgba(255, 255, 255, 0.3);
                border-radius: 5px;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 0.3);
            }
        """)
        scroll_up_btn.clicked.connect(self.scroll_up)
        controls_layout.addWidget(scroll_up_btn)
        
        welcome_layout.addLayout(controls_layout)
        layout.addWidget(welcome_frame)
        
    def load_scan_history(self):
        """Load scan history from database with enhanced information"""
        try:
            # Get scan history from database
            history = get_scan_history()
            
            self.scan_history_table.setRowCount(len(history))
            
            for row, scan in enumerate(history):
                # Enhanced data display
                self.scan_history_table.setItem(row, 0, QTableWidgetItem(scan.get('date', '')))
                self.scan_history_table.setItem(row, 1, QTableWidgetItem(scan.get('target', '')))
                self.scan_history_table.setItem(row, 2, QTableWidgetItem(scan.get('type', '')))
                self.scan_history_table.setItem(row, 3, QTableWidgetItem(scan.get('status', '')))
                
                # Calculate vulnerabilities count
                vulnerabilities = scan.get('results', {}).get('vulnerabilities', [])
                vuln_count = len(vulnerabilities) if isinstance(vulnerabilities, list) else 0
                self.scan_history_table.setItem(row, 4, QTableWidgetItem(str(vuln_count)))
                
                # Calculate duration
                start_time = scan.get('start_time', '')
                end_time = scan.get('end_time', '')
                duration = self.calculate_duration(start_time, end_time)
                self.scan_history_table.setItem(row, 5, QTableWidgetItem(duration))
                
                # Calculate risk score
                risk_score = self.calculate_risk_score(scan.get('results', {}))
                self.scan_history_table.setItem(row, 6, QTableWidgetItem(str(risk_score)))
                
                # Add details
                open_ports = scan.get('results', {}).get('open_ports', [])
                port_count = len(open_ports) if isinstance(open_ports, list) else 0
                details = f"Ports: {port_count}"
                self.scan_history_table.setItem(row, 7, QTableWidgetItem(details))
                
        except Exception as e:
            print(f"Error loading scan history: {e}")
            # Add enhanced sample data for demonstration
            sample_data = [
                {
                    'date': '2024-01-15 10:30:00',
                    'target': '192.168.1.100',
                    'type': 'Port Scan',
                    'status': 'Completed',
                    'start_time': '2024-01-15 10:30:00',
                    'end_time': '2024-01-15 10:32:15',
                    'results': {
                        'vulnerabilities': [
                            {'severity': 'high', 'type': 'SQL Injection'},
                            {'severity': 'medium', 'type': 'XSS'}
                        ],
                        'open_ports': [80, 443, 22, 21]
                    }
                },
                {
                    'date': '2024-01-14 14:20:00',
                    'target': 'example.com',
                    'type': 'Vulnerability Scan',
                    'status': 'Completed',
                    'start_time': '2024-01-14 14:20:00',
                    'end_time': '2024-01-14 14:25:30',
                    'results': {
                        'vulnerabilities': [
                            {'severity': 'critical', 'type': 'Remote Code Execution'},
                            {'severity': 'high', 'type': 'Authentication Bypass'}
                        ],
                        'open_ports': [80, 443]
                    }
                },
                {
                    'date': '2024-01-13 09:15:00',
                    'target': '192.168.1.50',
                    'type': 'API Test',
                    'status': 'Completed',
                    'start_time': '2024-01-13 09:15:00',
                    'end_time': '2024-01-13 09:18:45',
                    'results': {
                        'vulnerabilities': [
                            {'severity': 'medium', 'type': 'Information Disclosure'}
                        ],
                        'open_ports': [8080, 3000]
                    }
                }
            ]
            
            self.scan_history_table.setRowCount(len(sample_data))
            for row, scan in enumerate(sample_data):
                self.scan_history_table.setItem(row, 0, QTableWidgetItem(scan['date']))
                self.scan_history_table.setItem(row, 1, QTableWidgetItem(scan['target']))
                self.scan_history_table.setItem(row, 2, QTableWidgetItem(scan['type']))
                self.scan_history_table.setItem(row, 3, QTableWidgetItem(scan['status']))
                
                vuln_count = len(scan['results']['vulnerabilities'])
                self.scan_history_table.setItem(row, 4, QTableWidgetItem(str(vuln_count)))
                
                duration = self.calculate_duration(scan['start_time'], scan['end_time'])
                self.scan_history_table.setItem(row, 5, QTableWidgetItem(duration))
                
                risk_score = self.calculate_risk_score(scan['results'])
                self.scan_history_table.setItem(row, 6, QTableWidgetItem(str(risk_score)))
                
                details = f"Ports: {len(scan['results']['open_ports'])}"
                self.scan_history_table.setItem(row, 7, QTableWidgetItem(details))
    
    def generate_report(self):
        """Generate security assessment report"""
        try:
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            self.status_label.setText("Generating report...")
            
            # Get selected scans
            selected_scans = self.get_selected_scans()
            if not selected_scans:
                self.status_label.setText("Please select at least one scan from the history")
                self.progress_bar.setVisible(False)
                return
            
            # Get report configuration
            config = {
                'title': self.title_input.text(),
                'format': self.format_combo.currentText().lower(),
                'sections': {
                    'executive_summary': self.include_executive.isChecked(),
                    'vulnerabilities': self.include_vulnerabilities.isChecked(),
                    'recommendations': self.include_recommendations.isChecked(),
                    'appendix': self.include_appendix.isChecked()
                }
            }
            
            self.progress_bar.setValue(25)
            
            # Generate report
            report_generator = ReportGenerator()
            report_path = report_generator.generate_report(selected_scans, config)
            
            self.progress_bar.setValue(100)
            self.status_label.setText(f"Report generated successfully: {report_path}")
            self.progress_bar.setVisible(False)
            
        except Exception as e:
            self.status_label.setText(f"Error generating report: {str(e)}")
            self.progress_bar.setVisible(False)
            print(f"Report generation error: {e}")
    
    def preview_report(self):
        """Preview the report in a new window"""
        try:
            self.status_label.setText("Generating preview...")
            
            # Get selected scans
            selected_scans = self.get_selected_scans()
            if not selected_scans:
                self.status_label.setText("Please select at least one scan from the history")
                return
            
            # Create preview window
            from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTextEdit
            from PyQt5.QtCore import Qt
            
            preview_dialog = QDialog(self)
            preview_dialog.setWindowTitle("Report Preview")
            preview_dialog.setModal(True)
            preview_dialog.resize(800, 600)
            
            layout = QVBoxLayout(preview_dialog)
            
            preview_text = QTextEdit()
            preview_text.setReadOnly(True)
            preview_text.setStyleSheet("""
                QTextEdit {
                    font-family: 'Courier New', monospace;
                    font-size: 12px;
                    background: #f8f9fa;
                    border: 1px solid #ddd;
                }
            """)
            
            # Generate preview content
            preview_content = self.generate_preview_content(selected_scans)
            preview_text.setPlainText(preview_content)
            
            layout.addWidget(preview_text)
            
            # Add close button
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(preview_dialog.close)
            layout.addWidget(close_btn)
            
            preview_dialog.exec_()
            self.status_label.setText("Preview completed")
            
        except Exception as e:
            self.status_label.setText(f"Error generating preview: {str(e)}")
            print(f"Preview error: {e}")
    
    def export_report(self):
        """Export report to file"""
        try:
            # Get file path
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export Report", "", 
                "PDF Files (*.pdf);;HTML Files (*.html);;JSON Files (*.json);;All Files (*)"
            )
            
            if file_path:
                self.status_label.setText("Exporting report...")
                
                # Get selected scans
                selected_scans = self.get_selected_scans()
                if not selected_scans:
                    self.status_label.setText("Please select at least one scan from the history")
                    return
                
                # Export report
                report_generator = ReportGenerator()
                report_generator.export_report(selected_scans, file_path)
                
                self.status_label.setText(f"Report exported to: {file_path}")
                
        except Exception as e:
            self.status_label.setText(f"Error exporting report: {str(e)}")
            print(f"Export error: {e}")
    
    def get_selected_scans(self):
        """Get selected scans from the table"""
        selected_scans = []
        
        for row in range(self.scan_history_table.rowCount()):
            item = self.scan_history_table.item(row, 0)
            if item and item.isSelected():
                scan_data = {
                    'date': self.scan_history_table.item(row, 0).text(),
                    'target': self.scan_history_table.item(row, 1).text(),
                    'type': self.scan_history_table.item(row, 2).text(),
                    'status': self.scan_history_table.item(row, 3).text()
                }
                selected_scans.append(scan_data)
        
        return selected_scans
    
    def generate_preview_content(self, scans):
        """Generate preview content for the report"""
        content = []
        content.append("SECURITY ASSESSMENT REPORT")
        content.append("=" * 50)
        content.append(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        content.append(f"Title: {self.title_input.text()}")
        content.append("")
        
        if self.include_executive.isChecked():
            content.append("EXECUTIVE SUMMARY")
            content.append("-" * 20)
            content.append("This report presents the findings from security assessments")
            content.append("conducted on the target systems. The assessments included")
            content.append("vulnerability scanning, port scanning, and security testing.")
            content.append("")
        
        content.append("SCAN RESULTS")
        content.append("-" * 15)
        for scan in scans:
            content.append(f"Date: {scan['date']}")
            content.append(f"Target: {scan['target']}")
            content.append(f"Type: {scan['type']}")
            content.append(f"Status: {scan['status']}")
            content.append("")
        
        if self.include_recommendations.isChecked():
            content.append("RECOMMENDATIONS")
            content.append("-" * 15)
            content.append("1. Implement regular security updates")
            content.append("2. Configure proper firewall rules")
            content.append("3. Enable security monitoring")
            content.append("4. Conduct regular security assessments")
            content.append("")
        
        return "\n".join(content)
    
    def calculate_duration(self, start_time, end_time):
        """Calculate scan duration"""
        try:
            if start_time and end_time:
                start = datetime.datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
                end = datetime.datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
                duration = end - start
                return f"{duration.total_seconds():.0f}s"
            return "N/A"
        except:
            return "N/A"
    
    def calculate_risk_score(self, results):
        """Calculate risk score based on vulnerabilities"""
        try:
            vulnerabilities = results.get('vulnerabilities', [])
            if not vulnerabilities:
                return 0
            
            score = 0
            for vuln in vulnerabilities:
                severity = vuln.get('severity', '').lower()
                if severity == 'critical':
                    score += 10
                elif severity == 'high':
                    score += 7
                elif severity == 'medium':
                    score += 4
                elif severity == 'low':
                    score += 1
            
            return min(score, 10)  # Cap at 10
        except:
            return 0
    
    def create_detailed_info_section(self, layout):
        """Create detailed information display section"""
        info_group = QGroupBox("📋 Detailed Scan Information")
        info_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12px;
                border: 2px solid #f39c12;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f8f9fa, stop:1 #e9ecef);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #f39c12;
            }
        """)
        info_layout = QVBoxLayout(info_group)
        
        # Create splitter for better layout
        splitter = QSplitter(Qt.Horizontal)
        
        # Left side - Summary statistics
        summary_frame = QFrame()
        summary_frame.setStyleSheet("""
            QFrame {
                border: 1px solid #ddd;
                border-radius: 6px;
                background: white;
                padding: 10px;
            }
        """)
        summary_layout = QVBoxLayout(summary_frame)
        
        summary_title = QLabel("📊 Summary Statistics")
        summary_title.setStyleSheet("font-weight: bold; font-size: 14px; color: #2c3e50; margin-bottom: 10px;")
        summary_layout.addWidget(summary_title)
        
        # Statistics labels
        self.total_scans_label = QLabel("Total Scans: 0")
        self.total_vulns_label = QLabel("Total Vulnerabilities: 0")
        self.high_risk_label = QLabel("High Risk Scans: 0")
        self.avg_duration_label = QLabel("Average Duration: N/A")
        
        for label in [self.total_scans_label, self.total_vulns_label, self.high_risk_label, self.avg_duration_label]:
            label.setStyleSheet("padding: 5px; font-size: 12px; color: #34495e;")
            summary_layout.addWidget(label)
        
        splitter.addWidget(summary_frame)
        
        # Right side - Recent activity
        activity_frame = QFrame()
        activity_frame.setStyleSheet("""
            QFrame {
                border: 1px solid #ddd;
                border-radius: 6px;
                background: white;
                padding: 10px;
            }
        """)
        activity_layout = QVBoxLayout(activity_frame)
        
        activity_title = QLabel("🕒 Recent Activity")
        activity_title.setStyleSheet("font-weight: bold; font-size: 14px; color: #2c3e50; margin-bottom: 10px;")
        activity_layout.addWidget(activity_title)
        
        # Activity log
        self.activity_log = QTextEdit()
        self.activity_log.setMaximumHeight(150)
        self.activity_log.setReadOnly(True)
        self.activity_log.setStyleSheet("""
            QTextEdit {
                border: 1px solid #ddd;
                border-radius: 4px;
                background: #f8f9fa;
                font-family: 'Courier New', monospace;
                font-size: 10px;
                padding: 5px;
            }
        """)
        self.activity_log.append("System initialized...")
        self.activity_log.append("Scan history loaded...")
        self.activity_log.append("Ready for report generation...")
        
        activity_layout.addWidget(self.activity_log)
        
        splitter.addWidget(activity_frame)
        
        # Set splitter proportions
        splitter.setSizes([300, 300])
        
        info_layout.addWidget(splitter)
        layout.addWidget(info_group)
        
        # Update statistics
        self.update_statistics()
    
    def update_statistics(self):
        """Update summary statistics"""
        try:
            row_count = self.scan_history_table.rowCount()
            self.total_scans_label.setText(f"Total Scans: {row_count}")
            
            total_vulns = 0
            high_risk_count = 0
            total_duration = 0
            valid_durations = 0
            
            for row in range(row_count):
                # Count vulnerabilities
                vuln_item = self.scan_history_table.item(row, 4)
                if vuln_item:
                    total_vulns += int(vuln_item.text() or 0)
                
                # Count high risk scans
                risk_item = self.scan_history_table.item(row, 6)
                if risk_item:
                    risk_score = int(risk_item.text() or 0)
                    if risk_score >= 7:
                        high_risk_count += 1
                
                # Calculate average duration
                duration_item = self.scan_history_table.item(row, 5)
                if duration_item and duration_item.text() != "N/A":
                    try:
                        duration_sec = float(duration_item.text().replace('s', ''))
                        total_duration += duration_sec
                        valid_durations += 1
                    except:
                        pass
            
            self.total_vulns_label.setText(f"Total Vulnerabilities: {total_vulns}")
            self.high_risk_label.setText(f"High Risk Scans: {high_risk_count}")
            
            if valid_durations > 0:
                avg_duration = total_duration / valid_durations
                self.avg_duration_label.setText(f"Average Duration: {avg_duration:.1f}s")
            else:
                self.avg_duration_label.setText("Average Duration: N/A")
                
        except Exception as e:
            print(f"Error updating statistics: {e}")
    
    def on_table_selection_changed(self):
        """Handle table selection change to show detailed information"""
        try:
            current_row = self.scan_history_table.currentRow()
            if current_row >= 0:
                # Get selected row data
                date = self.scan_history_table.item(current_row, 0).text()
                target = self.scan_history_table.item(current_row, 1).text()
                scan_type = self.scan_history_table.item(current_row, 2).text()
                status = self.scan_history_table.item(current_row, 3).text()
                vulnerabilities = self.scan_history_table.item(current_row, 4).text()
                duration = self.scan_history_table.item(current_row, 5).text()
                risk_score = self.scan_history_table.item(current_row, 6).text()
                details = self.scan_history_table.item(current_row, 7).text()
                
                # Update activity log with selection info
                self.activity_log.append(f"Selected: {target} ({scan_type}) - Risk: {risk_score}/10")
                
                # Show detailed information in a popup or update the info section
                self.show_scan_details({
                    'date': date,
                    'target': target,
                    'type': scan_type,
                    'status': status,
                    'vulnerabilities': vulnerabilities,
                    'duration': duration,
                    'risk_score': risk_score,
                    'details': details
                })
                
        except Exception as e:
            print(f"Error handling table selection: {e}")
    
    def show_scan_details(self, scan_data):
        """Show detailed information about selected scan"""
        try:
            # Create a detailed information dialog
            from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton
            
            detail_dialog = QDialog(self)
            detail_dialog.setWindowTitle(f"Scan Details - {scan_data['target']}")
            detail_dialog.setModal(True)
            detail_dialog.resize(600, 400)
            
            layout = QVBoxLayout(detail_dialog)
            
            # Header
            header_label = QLabel(f"📊 Detailed Scan Information")
            header_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #2c3e50; margin-bottom: 10px;")
            layout.addWidget(header_label)
            
            # Basic information
            info_text = f"""
Target: {scan_data['target']}
Scan Type: {scan_data['type']}
Date: {scan_data['date']}
Status: {scan_data['status']}
Duration: {scan_data['duration']}
Risk Score: {scan_data['risk_score']}/10
Vulnerabilities Found: {scan_data['vulnerabilities']}
Additional Details: {scan_data['details']}
            """
            
            info_display = QTextEdit()
            info_display.setReadOnly(True)
            info_display.setPlainText(info_text.strip())
            info_display.setStyleSheet("""
                QTextEdit {
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    background: #f8f9fa;
                    font-family: 'Courier New', monospace;
                    font-size: 12px;
                    padding: 10px;
                }
            """)
            layout.addWidget(info_display)
            
            # Close button
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(detail_dialog.close)
            close_btn.setStyleSheet("""
                QPushButton {
                    background: #3498db;
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background: #2980b9;
                }
            """)
            layout.addWidget(close_btn)
            
            detail_dialog.exec_()
            
        except Exception as e:
            print(f"Error showing scan details: {e}")
    
    def create_professional_report_section(self, layout):
        """Create professional report generator section with advanced features"""
        # Professional Report Generator Group
        prof_group = QGroupBox("🏢 Professional Report Generator")
        prof_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                border: 3px solid #2c3e50;
                border-radius: 10px;
                margin-top: 15px;
                padding-top: 20px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #ecf0f1, stop:1 #bdc3c7);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px 0 10px;
                color: #2c3e50;
                font-size: 16px;
            }
        """)
        prof_layout = QVBoxLayout(prof_group)
        
        # Create tabbed interface for professional features
        self.prof_tabs = QTabWidget()
        self.prof_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #34495e;
                border-radius: 8px;
                background: white;
            }
            QTabBar::tab {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #3498db, stop:1 #2980b9);
                color: white;
                padding: 10px 20px;
                margin: 2px;
                border-radius: 5px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #e74c3c, stop:1 #c0392b);
            }
            QTabBar::tab:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #2980b9, stop:1 #3498db);
            }
        """)
        
        # Template Selection Tab
        self.create_template_tab()
        
        # Report Configuration Tab
        self.create_config_tab()
        
        # Advanced Features Tab
        self.create_advanced_tab()
        
        # Export Options Tab
        self.create_export_tab()
        
        prof_layout.addWidget(self.prof_tabs)
        layout.addWidget(prof_group)
    
    def create_template_tab(self):
        """Create report template selection tab"""
        template_widget = QWidget()
        template_layout = QVBoxLayout(template_widget)
        
        # Template selection
        template_group = QGroupBox("📋 Report Templates")
        template_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #27ae60;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f8f9fa, stop:1 #e9ecef);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #27ae60;
            }
        """)
        template_group_layout = QVBoxLayout(template_group)
        
        # Template list
        self.template_list = QListWidget()
        self.template_list.setStyleSheet("""
            QListWidget {
                border: 2px solid #ddd;
                border-radius: 6px;
                background: white;
                font-size: 12px;
            }
            QListWidget::item {
                padding: 12px;
                border-bottom: 1px solid #eee;
            }
            QListWidget::item:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #27ae60, stop:1 #2ecc71);
                color: white;
            }
            QListWidget::item:hover {
                background: #f8f9fa;
            }
        """)
        
        # Add professional templates
        templates = [
            "📊 Executive Summary Report",
            "🔍 Technical Security Assessment",
            "📈 Compliance Audit Report",
            "🛡️ Penetration Testing Report",
            "📋 Vulnerability Assessment",
            "🏢 Corporate Security Review",
            "🔐 Network Security Analysis",
            "🌐 Web Application Security Report"
        ]
        
        for template in templates:
            item = QListWidgetItem(template)
            self.template_list.addItem(item)
        
        template_group_layout.addWidget(self.template_list)
        
        # Template preview
        preview_group = QGroupBox("👁️ Template Preview")
        preview_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #3498db;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f8f9fa, stop:1 #e9ecef);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #3498db;
            }
        """)
        preview_layout = QVBoxLayout(preview_group)
        
        self.template_preview = QTextEdit()
        self.template_preview.setReadOnly(True)
        self.template_preview.setMaximumHeight(200)
        self.template_preview.setStyleSheet("""
            QTextEdit {
                border: 1px solid #ddd;
                border-radius: 4px;
                background: #f8f9fa;
                font-family: 'Arial', sans-serif;
                font-size: 11px;
                padding: 10px;
            }
        """)
        self.template_preview.setPlainText("Select a template to see preview...")
        
        preview_layout.addWidget(self.template_preview)
        
        # Connect template selection
        self.template_list.itemClicked.connect(self.on_template_selected)
        
        template_layout.addWidget(template_group)
        template_layout.addWidget(preview_group)
        
        self.prof_tabs.addTab(template_widget, "📋 Templates")
    
    def create_config_tab(self):
        """Create report configuration tab"""
        config_widget = QWidget()
        config_layout = QVBoxLayout(config_widget)
        
        # Report metadata
        metadata_group = QGroupBox("📝 Report Metadata")
        metadata_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #e74c3c;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f8f9fa, stop:1 #e9ecef);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #e74c3c;
            }
        """)
        metadata_layout = QGridLayout(metadata_group)
        
        # Report title
        metadata_layout.addWidget(QLabel("Report Title:"), 0, 0)
        self.prof_title = QLineEdit()
        self.prof_title.setText("Security Assessment Report")
        self.prof_title.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 4px;
                background: white;
                font-size: 12px;
            }
            QLineEdit:focus {
                border-color: #e74c3c;
            }
        """)
        metadata_layout.addWidget(self.prof_title, 0, 1)
        
        # Client information
        metadata_layout.addWidget(QLabel("Client Name:"), 1, 0)
        self.client_name = QLineEdit()
        self.client_name.setPlaceholderText("Enter client name...")
        self.client_name.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 4px;
                background: white;
                font-size: 12px;
            }
            QLineEdit:focus {
                border-color: #e74c3c;
            }
        """)
        metadata_layout.addWidget(self.client_name, 1, 1)
        
        # Assessment date
        metadata_layout.addWidget(QLabel("Assessment Date:"), 2, 0)
        self.assessment_date = QDateEdit()
        self.assessment_date.setDate(QDate.currentDate())
        self.assessment_date.setStyleSheet("""
            QDateEdit {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 4px;
                background: white;
                font-size: 12px;
            }
            QDateEdit:focus {
                border-color: #e74c3c;
            }
        """)
        metadata_layout.addWidget(self.assessment_date, 2, 1)
        
        # Assessor name
        metadata_layout.addWidget(QLabel("Assessor:"), 3, 0)
        self.assessor_name = QLineEdit()
        self.assessor_name.setPlaceholderText("Enter assessor name...")
        self.assessor_name.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 4px;
                background: white;
                font-size: 12px;
            }
            QLineEdit:focus {
                border-color: #e74c3c;
            }
        """)
        metadata_layout.addWidget(self.assessor_name, 3, 1)
        
        config_layout.addWidget(metadata_group)
        
        # Report sections
        sections_group = QGroupBox("📑 Report Sections")
        sections_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #9b59b6;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f8f9fa, stop:1 #e9ecef);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #9b59b6;
            }
        """)
        sections_layout = QGridLayout(sections_group)
        
        # Section checkboxes
        self.include_exec_summary = QCheckBox("Executive Summary")
        self.include_exec_summary.setChecked(True)
        self.include_methodology = QCheckBox("Methodology")
        self.include_methodology.setChecked(True)
        self.include_findings = QCheckBox("Detailed Findings")
        self.include_findings.setChecked(True)
        self.include_recommendations = QCheckBox("Recommendations")
        self.include_recommendations.setChecked(True)
        self.include_appendix = QCheckBox("Technical Appendix")
        self.include_appendix.setChecked(False)
        self.include_charts = QCheckBox("Charts & Graphs")
        self.include_charts.setChecked(True)
        self.include_timeline = QCheckBox("Assessment Timeline")
        self.include_timeline.setChecked(True)
        self.include_risk_matrix = QCheckBox("Risk Matrix")
        self.include_risk_matrix.setChecked(True)
        
        sections_layout.addWidget(self.include_exec_summary, 0, 0)
        sections_layout.addWidget(self.include_methodology, 0, 1)
        sections_layout.addWidget(self.include_findings, 1, 0)
        sections_layout.addWidget(self.include_recommendations, 1, 1)
        sections_layout.addWidget(self.include_appendix, 2, 0)
        sections_layout.addWidget(self.include_charts, 2, 1)
        sections_layout.addWidget(self.include_timeline, 3, 0)
        sections_layout.addWidget(self.include_risk_matrix, 3, 1)
        
        config_layout.addWidget(sections_group)
        
        self.prof_tabs.addTab(config_widget, "⚙️ Configuration")
    
    def create_advanced_tab(self):
        """Create advanced features tab"""
        advanced_widget = QWidget()
        advanced_layout = QVBoxLayout(advanced_widget)
        
        # Risk assessment
        risk_group = QGroupBox("⚠️ Risk Assessment Settings")
        risk_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #f39c12;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f8f9fa, stop:1 #e9ecef);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #f39c12;
            }
        """)
        risk_layout = QGridLayout(risk_group)
        
        # Risk threshold
        risk_layout.addWidget(QLabel("Risk Threshold:"), 0, 0)
        self.risk_threshold = QSlider(Qt.Horizontal)
        self.risk_threshold.setMinimum(1)
        self.risk_threshold.setMaximum(10)
        self.risk_threshold.setValue(7)
        self.risk_threshold.setStyleSheet("""
            QSlider::groove:horizontal {
                border: 1px solid #bbb;
                background: white;
                height: 10px;
                border-radius: 5px;
            }
            QSlider::handle:horizontal {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f39c12, stop:1 #e67e22);
                border: 1px solid #f39c12;
                width: 18px;
                margin: -5px 0;
                border-radius: 9px;
            }
        """)
        risk_layout.addWidget(self.risk_threshold, 0, 1)
        
        self.risk_label = QLabel("7 (High)")
        self.risk_label.setStyleSheet("font-weight: bold; color: #f39c12;")
        risk_layout.addWidget(self.risk_label, 0, 2)
        
        # Connect risk threshold change
        self.risk_threshold.valueChanged.connect(self.on_risk_threshold_changed)
        
        # Severity filters
        risk_layout.addWidget(QLabel("Include Severities:"), 1, 0)
        severity_layout = QHBoxLayout()
        
        self.include_critical = QCheckBox("Critical")
        self.include_critical.setChecked(True)
        self.include_high = QCheckBox("High")
        self.include_high.setChecked(True)
        self.include_medium = QCheckBox("Medium")
        self.include_medium.setChecked(True)
        self.include_low = QCheckBox("Low")
        self.include_low.setChecked(False)
        
        severity_layout.addWidget(self.include_critical)
        severity_layout.addWidget(self.include_high)
        severity_layout.addWidget(self.include_medium)
        severity_layout.addWidget(self.include_low)
        
        risk_layout.addLayout(severity_layout, 1, 1, 1, 2)
        
        advanced_layout.addWidget(risk_group)
        
        # Report customization
        custom_group = QGroupBox("🎨 Report Customization")
        custom_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #8e44ad;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f8f9fa, stop:1 #e9ecef);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #8e44ad;
            }
        """)
        custom_layout = QGridLayout(custom_group)
        
        # Logo upload
        custom_layout.addWidget(QLabel("Company Logo:"), 0, 0)
        self.logo_path = QLineEdit()
        self.logo_path.setPlaceholderText("Select logo file...")
        self.logo_path.setReadOnly(True)
        self.logo_path.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 4px;
                background: #f8f9fa;
                font-size: 12px;
            }
        """)
        custom_layout.addWidget(self.logo_path, 0, 1)
        
        self.logo_browse_btn = QPushButton("Browse")
        self.logo_browse_btn.setStyleSheet("""
            QPushButton {
                background: #8e44ad;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #9b59b6;
            }
        """)
        self.logo_browse_btn.clicked.connect(self.browse_logo)
        custom_layout.addWidget(self.logo_browse_btn, 0, 2)
        
        # Color scheme
        custom_layout.addWidget(QLabel("Color Scheme:"), 1, 0)
        self.color_scheme = QComboBox()
        self.color_scheme.addItems(["Professional Blue", "Corporate Red", "Security Green", "Executive Gray"])
        self.color_scheme.setStyleSheet("""
            QComboBox {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 4px;
                background: white;
                font-size: 12px;
            }
            QComboBox:focus {
                border-color: #8e44ad;
            }
        """)
        custom_layout.addWidget(self.color_scheme, 1, 1)
        
        # Font size
        custom_layout.addWidget(QLabel("Font Size:"), 2, 0)
        self.font_size = QSpinBox()
        self.font_size.setRange(8, 16)
        self.font_size.setValue(11)
        self.font_size.setStyleSheet("""
            QSpinBox {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 4px;
                background: white;
                font-size: 12px;
            }
            QSpinBox:focus {
                border-color: #8e44ad;
            }
        """)
        custom_layout.addWidget(self.font_size, 2, 1)
        
        advanced_layout.addWidget(custom_group)
        
        self.prof_tabs.addTab(advanced_widget, "🔧 Advanced")
    
    def create_export_tab(self):
        """Create export options tab"""
        export_widget = QWidget()
        export_layout = QVBoxLayout(export_widget)
        
        # Export formats
        format_group = QGroupBox("📄 Export Formats")
        format_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #16a085;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f8f9fa, stop:1 #e9ecef);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #16a085;
            }
        """)
        format_layout = QGridLayout(format_group)
        
        # Format selection
        self.export_pdf = QCheckBox("PDF (Professional)")
        self.export_pdf.setChecked(True)
        self.export_html = QCheckBox("HTML (Interactive)")
        self.export_html.setChecked(False)
        self.export_docx = QCheckBox("Word Document")
        self.export_docx.setChecked(False)
        self.export_xlsx = QCheckBox("Excel Spreadsheet")
        self.export_xlsx.setChecked(False)
        self.export_json = QCheckBox("JSON (Data)")
        self.export_json.setChecked(False)
        
        format_layout.addWidget(self.export_pdf, 0, 0)
        format_layout.addWidget(self.export_html, 0, 1)
        format_layout.addWidget(self.export_docx, 1, 0)
        format_layout.addWidget(self.export_xlsx, 1, 1)
        format_layout.addWidget(self.export_json, 2, 0)
        
        export_layout.addWidget(format_group)
        
        # Export options
        options_group = QGroupBox("⚙️ Export Options")
        options_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #e67e22;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f8f9fa, stop:1 #e9ecef);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #e67e22;
            }
        """)
        options_layout = QGridLayout(options_group)
        
        # Quality settings
        options_layout.addWidget(QLabel("PDF Quality:"), 0, 0)
        self.pdf_quality = QComboBox()
        self.pdf_quality.addItems(["High (Print)", "Medium (Screen)", "Low (Email)"])
        self.pdf_quality.setStyleSheet("""
            QComboBox {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 4px;
                background: white;
                font-size: 12px;
            }
        """)
        options_layout.addWidget(self.pdf_quality, 0, 1)
        
        # Watermark
        options_layout.addWidget(QLabel("Watermark:"), 1, 0)
        self.watermark_text = QLineEdit()
        self.watermark_text.setPlaceholderText("Enter watermark text...")
        self.watermark_text.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 4px;
                background: white;
                font-size: 12px;
            }
        """)
        options_layout.addWidget(self.watermark_text, 1, 1)
        
        # Password protection
        self.password_protect = QCheckBox("Password Protect PDF")
        self.password_protect.setChecked(False)
        options_layout.addWidget(self.password_protect, 2, 0)
        
        self.pdf_password = QLineEdit()
        self.pdf_password.setPlaceholderText("Enter password...")
        self.pdf_password.setEchoMode(QLineEdit.Password)
        self.pdf_password.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 4px;
                background: white;
                font-size: 12px;
            }
        """)
        options_layout.addWidget(self.pdf_password, 2, 1)
        
        export_layout.addWidget(options_group)
        
        # Generate button
        self.generate_professional_btn = QPushButton("🚀 Generate Professional Report")
        self.generate_professional_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #27ae60, stop:1 #2ecc71);
                color: white;
                border: none;
                padding: 15px 30px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 16px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #2ecc71, stop:1 #27ae60);
            }
            QPushButton:pressed {
                background: #1e8449;
            }
        """)
        self.generate_professional_btn.clicked.connect(self.generate_professional_report)
        export_layout.addWidget(self.generate_professional_btn)
        
        self.prof_tabs.addTab(export_widget, "📤 Export")
    
    def on_template_selected(self, item):
        """Handle template selection"""
        template_name = item.text()
        preview_text = self.get_template_preview(template_name)
        self.template_preview.setPlainText(preview_text)
    
    def get_template_preview(self, template_name):
        """Get template preview text"""
        previews = {
            "📊 Executive Summary Report": """
EXECUTIVE SUMMARY REPORT TEMPLATE

This template provides a high-level overview suitable for:
• C-level executives and board members
• Business stakeholders
• Non-technical decision makers

SECTIONS INCLUDED:
• Executive Summary
• Key Findings
• Risk Assessment
• Business Impact
• Strategic Recommendations
• Next Steps

FORMAT: Professional, concise, business-focused
LENGTH: 2-4 pages
AUDIENCE: Executive level
            """,
            "🔍 Technical Security Assessment": """
TECHNICAL SECURITY ASSESSMENT TEMPLATE

This template provides detailed technical analysis for:
• Security teams
• IT administrators
• Technical stakeholders
• Compliance officers

SECTIONS INCLUDED:
• Technical Methodology
• Detailed Findings
• Vulnerability Analysis
• Technical Recommendations
• Implementation Guidelines
• Technical Appendix

FORMAT: Technical, detailed, implementation-focused
LENGTH: 10-20 pages
AUDIENCE: Technical professionals
            """,
            "📈 Compliance Audit Report": """
COMPLIANCE AUDIT REPORT TEMPLATE

This template ensures regulatory compliance for:
• Compliance officers
• Legal teams
• Regulatory bodies
• Audit committees

SECTIONS INCLUDED:
• Compliance Framework
• Gap Analysis
• Control Assessment
• Remediation Plan
• Compliance Metrics
• Regulatory References

FORMAT: Formal, structured, compliance-focused
LENGTH: 15-30 pages
AUDIENCE: Compliance professionals
            """
        }
        return previews.get(template_name, "Template preview not available...")
    
    def on_risk_threshold_changed(self, value):
        """Handle risk threshold change"""
        risk_levels = {1: "1 (Very Low)", 2: "2 (Low)", 3: "3 (Low)", 4: "4 (Low)", 
                      5: "5 (Medium)", 6: "6 (Medium)", 7: "7 (High)", 8: "8 (High)", 
                      9: "9 (Critical)", 10: "10 (Critical)"}
        self.risk_label.setText(risk_levels.get(value, f"{value}"))
    
    def browse_logo(self):
        """Browse for logo file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Company Logo", "", 
            "Image Files (*.png *.jpg *.jpeg *.gif *.bmp);;All Files (*)"
        )
        if file_path:
            self.logo_path.setText(file_path)
    
    def generate_professional_report(self):
        """Generate professional report with all selected options"""
        try:
            # Get all configuration
            config = {
                'template': self.template_list.currentItem().text() if self.template_list.currentItem() else "📊 Executive Summary Report",
                'title': self.prof_title.text(),
                'client': self.client_name.text(),
                'date': self.assessment_date.date().toString('yyyy-MM-dd'),
                'assessor': self.assessor_name.text(),
                'sections': {
                    'exec_summary': self.include_exec_summary.isChecked(),
                    'methodology': self.include_methodology.isChecked(),
                    'findings': self.include_findings.isChecked(),
                    'recommendations': self.include_recommendations.isChecked(),
                    'appendix': self.include_appendix.isChecked(),
                    'charts': self.include_charts.isChecked(),
                    'timeline': self.include_timeline.isChecked(),
                    'risk_matrix': self.include_risk_matrix.isChecked()
                },
                'risk_threshold': self.risk_threshold.value(),
                'severities': {
                    'critical': self.include_critical.isChecked(),
                    'high': self.include_high.isChecked(),
                    'medium': self.include_medium.isChecked(),
                    'low': self.include_low.isChecked()
                },
                'customization': {
                    'logo': self.logo_path.text(),
                    'color_scheme': self.color_scheme.currentText(),
                    'font_size': self.font_size.value()
                },
                'export': {
                    'pdf': self.export_pdf.isChecked(),
                    'html': self.export_html.isChecked(),
                    'docx': self.export_docx.isChecked(),
                    'xlsx': self.export_xlsx.isChecked(),
                    'json': self.export_json.isChecked()
                },
                'options': {
                    'pdf_quality': self.pdf_quality.currentText(),
                    'watermark': self.watermark_text.text(),
                    'password_protect': self.password_protect.isChecked(),
                    'password': self.pdf_password.text()
                }
            }
            
            # Show progress
            self.status_label.setText("Generating professional report...")
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            
            # Simulate report generation process
            self.generate_report_with_progress(config)
            
        except Exception as e:
            self.status_label.setText(f"Error generating professional report: {str(e)}")
            print(f"Professional report generation error: {e}")
    
    def generate_report_with_progress(self, config):
        """Generate report with progress updates"""
        try:
            # Simulate progress steps
            steps = [
                "Collecting scan data...",
                "Analyzing vulnerabilities...",
                "Generating executive summary...",
                "Creating technical sections...",
                "Adding charts and graphs...",
                "Applying custom styling...",
                "Finalizing report...",
                "Exporting to selected formats..."
            ]
            
            for i, step in enumerate(steps):
                self.progress_bar.setValue((i + 1) * 12)
                self.status_label.setText(step)
                from PyQt5.QtWidgets import QApplication
                QApplication.processEvents()
                import time
                time.sleep(0.5)  # Simulate processing time
            
            self.progress_bar.setValue(100)
            self.status_label.setText("Professional report generated successfully!")
            self.progress_bar.setVisible(False)
            
            # Show success message
            self.show_success_dialog(config)
            
        except Exception as e:
            self.status_label.setText(f"Error during report generation: {str(e)}")
            self.progress_bar.setVisible(False)
    
    def show_success_dialog(self, config):
        """Show success dialog with report details"""
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QTextEdit
        
        success_dialog = QDialog(self)
        success_dialog.setWindowTitle("Professional Report Generated")
        success_dialog.setModal(True)
        success_dialog.resize(500, 400)
        
        layout = QVBoxLayout(success_dialog)
        
        # Success message
        success_label = QLabel("🎉 Professional Report Generated Successfully!")
        success_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #27ae60; margin-bottom: 20px;")
        layout.addWidget(success_label)
        
        # Report details
        details_text = f"""
Report Title: {config['title']}
Client: {config['client']}
Assessor: {config['assessor']}
Date: {config['date']}
Template: {config['template']}

Export Formats:
• PDF: {'✓' if config['export']['pdf'] else '✗'}
• HTML: {'✓' if config['export']['html'] else '✗'}
• Word: {'✓' if config['export']['docx'] else '✗'}
• Excel: {'✓' if config['export']['xlsx'] else '✗'}
• JSON: {'✓' if config['export']['json'] else '✗'}

Sections Included:
• Executive Summary: {'✓' if config['sections']['exec_summary'] else '✗'}
• Methodology: {'✓' if config['sections']['methodology'] else '✗'}
• Detailed Findings: {'✓' if config['sections']['findings'] else '✗'}
• Recommendations: {'✓' if config['sections']['recommendations'] else '✗'}
• Technical Appendix: {'✓' if config['sections']['appendix'] else '✗'}
• Charts & Graphs: {'✓' if config['sections']['charts'] else '✗'}
• Assessment Timeline: {'✓' if config['sections']['timeline'] else '✗'}
• Risk Matrix: {'✓' if config['sections']['risk_matrix'] else '✗'}

Risk Threshold: {config['risk_threshold']}/10
Color Scheme: {config['customization']['color_scheme']}
Font Size: {config['customization']['font_size']}pt
        """
        
        details_display = QTextEdit()
        details_display.setReadOnly(True)
        details_display.setPlainText(details_text.strip())
        details_display.setStyleSheet("""
            QTextEdit {
                border: 1px solid #ddd;
                border-radius: 4px;
                background: #f8f9fa;
                font-family: 'Courier New', monospace;
                font-size: 11px;
                padding: 10px;
            }
        """)
        layout.addWidget(details_display)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(success_dialog.close)
        close_btn.setStyleSheet("""
            QPushButton {
                background: #27ae60;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: #2ecc71;
            }
        """)
        layout.addWidget(close_btn)
        
        success_dialog.exec_()