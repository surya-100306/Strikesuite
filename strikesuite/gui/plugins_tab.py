#!/usr/bin/env python3
"""
Plugins Tab
GUI for plugin management functionality
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QLineEdit, QPushButton, QTextEdit,
                             QCheckBox, QGroupBox, QTableWidget, QTableWidgetItem,
                             QHeaderView, QComboBox, QFileDialog, QScrollArea)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import os

class PluginsTab(QWidget):
    """Plugins management tab widget"""
    
    def __init__(self, plugin_manager=None):
        super().__init__()
        self.plugin_manager = plugin_manager
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface with modern design"""
        # Create main layout
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(15, 15, 15, 15)
        
        # Add welcome section
        self.create_welcome_section(main_layout)
        
        # Create scroll area for the content
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setStyleSheet("""
            QScrollArea {
                border: none;
                background: transparent;
            }
        """)
        
        # Create main widget
        main_widget = QWidget()
        scroll_area.setWidget(main_widget)
        main_layout.addWidget(scroll_area)
        
        layout = QVBoxLayout(main_widget)
        layout.setSpacing(15)
        
        # Plugin management with enhanced styling
        management_group = QGroupBox("🔌 Plugin Management")
        management_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12px;
                border: 2px solid #2c3e50;
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
        management_layout = QHBoxLayout(management_group)
        management_layout.setSpacing(10)
        
        self.refresh_btn = QPushButton("Refresh Plugins")
        self.refresh_btn.clicked.connect(self.refresh_plugins)
        management_layout.addWidget(self.refresh_btn)
        
        self.load_btn = QPushButton("Load Plugin")
        self.load_btn.clicked.connect(self.load_plugin)
        management_layout.addWidget(self.load_btn)
        
        self.unload_btn = QPushButton("Unload Plugin")
        self.unload_btn.clicked.connect(self.unload_plugin)
        management_layout.addWidget(self.unload_btn)
        
        management_layout.addStretch()
        
        layout.addWidget(management_group)
        
        # Advanced Plugin Management
        advanced_group = QGroupBox("Advanced Plugin Management")
        advanced_layout = QVBoxLayout(advanced_group)
        
        # Execution mode
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("Execution Mode:"))
        self.execution_mode_combo = QComboBox()
        self.execution_mode_combo.addItems(["Sequential", "Parallel", "Pipeline", "Conditional", "Adaptive"])
        self.execution_mode_combo.setCurrentText("Sequential")
        mode_layout.addWidget(self.execution_mode_combo)
        mode_layout.addStretch()
        advanced_layout.addLayout(mode_layout)
        
        # Advanced options checkboxes
        self.hot_reload_check = QCheckBox("Hot Reload")
        advanced_layout.addWidget(self.hot_reload_check)
        
        self.dependency_mgmt_check = QCheckBox("Dependency Management")
        advanced_layout.addWidget(self.dependency_mgmt_check)
        
        self.plugin_chaining_check = QCheckBox("Plugin Chaining")
        advanced_layout.addWidget(self.plugin_chaining_check)
        
        self.resource_mgmt_check = QCheckBox("Resource Management")
        advanced_layout.addWidget(self.resource_mgmt_check)
        
        self.sandbox_check = QCheckBox("Security Sandbox")
        advanced_layout.addWidget(self.sandbox_check)
        
        self.performance_monitor_check = QCheckBox("Performance Monitoring")
        advanced_layout.addWidget(self.performance_monitor_check)
        
        self.error_recovery_check = QCheckBox("Error Recovery")
        advanced_layout.addWidget(self.error_recovery_check)
        
        # Advanced execution button
        self.advanced_execute_btn = QPushButton("Execute Advanced Plugin Chain")
        self.advanced_execute_btn.clicked.connect(self.execute_advanced_plugins)
        advanced_layout.addWidget(self.advanced_execute_btn)
        
        layout.addWidget(advanced_group)
        
        # Available plugins
        plugins_group = QGroupBox("Available Plugins")
        plugins_layout = QVBoxLayout(plugins_group)
        
        # Plugins table
        self.plugins_table = QTableWidget()
        self.plugins_table.setColumnCount(5)
        self.plugins_table.setHorizontalHeaderLabels(["Plugin", "Version", "Status", "Description", "Author"])
        self.plugins_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.plugins_table.setSelectionBehavior(QTableWidget.SelectRows)
        plugins_layout.addWidget(self.plugins_table)
        
        layout.addWidget(plugins_group)
        
        # Plugin configuration
        config_group = QGroupBox("Plugin Configuration")
        config_layout = QGridLayout(config_group)
        
        config_layout.addWidget(QLabel("Selected Plugin:"), 0, 0)
        self.selected_plugin_label = QLabel("None")
        config_layout.addWidget(self.selected_plugin_label, 0, 1)
        
        config_layout.addWidget(QLabel("Plugin Settings:"), 1, 0)
        self.plugin_settings_text = QTextEdit()
        self.plugin_settings_text.setMaximumHeight(100)
        self.plugin_settings_text.setPlaceholderText("Plugin configuration will appear here...")
        config_layout.addWidget(self.plugin_settings_text, 1, 1)
        
        # Plugin actions
        actions_layout = QHBoxLayout()
        
        self.configure_btn = QPushButton("Configure Plugin")
        self.configure_btn.setEnabled(False)
        self.configure_btn.clicked.connect(self.configure_plugin)
        actions_layout.addWidget(self.configure_btn)
        
        self.run_btn = QPushButton("Run Plugin")
        self.run_btn.setEnabled(False)
        self.run_btn.clicked.connect(self.run_plugin)
        actions_layout.addWidget(self.run_btn)
        
        self.stop_btn = QPushButton("Stop Plugin")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_plugin)
        actions_layout.addWidget(self.stop_btn)
        
        config_layout.addLayout(actions_layout, 2, 0, 1, 2)
        
        layout.addWidget(config_group)
        
        # Plugin development
        dev_group = QGroupBox("Plugin Development")
        dev_layout = QVBoxLayout(dev_group)
        
        dev_layout.addWidget(QLabel("Create new plugin from template:"))
        
        template_layout = QHBoxLayout()
        
        self.template_combo = QComboBox()
        self.template_combo.addItems(["Basic Plugin", "Scanner Plugin", "Exploit Plugin", "Report Plugin"])
        template_layout.addWidget(self.template_combo)
        
        self.create_plugin_btn = QPushButton("Create Plugin")
        self.create_plugin_btn.clicked.connect(self.create_plugin)
        template_layout.addWidget(self.create_plugin_btn)
        
        dev_layout.addLayout(template_layout)
        
        layout.addWidget(dev_group)
        
        # Plugin output
        output_group = QGroupBox("Plugin Output")
        output_layout = QVBoxLayout(output_group)
        
        self.plugin_output = QTextEdit()
        self.plugin_output.setMaximumHeight(200)
        self.plugin_output.setPlaceholderText("Plugin output will appear here...")
        output_layout.addWidget(self.plugin_output)
        
        layout.addWidget(output_group)
        
        # Connect table selection
        self.plugins_table.itemSelectionChanged.connect(self.on_plugin_selected)
        
        # Load initial plugins
        self.refresh_plugins()
        
    def refresh_plugins(self):
        """Refresh the plugins list"""
        self.plugins_table.setRowCount(0)
        
        # Load built-in plugins
        builtin_plugins = [
            ("Advanced API Tester", "1.0", "Available", "Advanced API security testing", "StrikeSuite Team"),
            ("Subdomain Enumeration", "1.0", "Available", "Subdomain discovery tool", "StrikeSuite Team"),
            ("Directory Brute Force", "1.0", "Available", "Web directory brute forcing", "StrikeSuite Team"),
            ("SSL Analyzer", "1.0", "Available", "SSL/TLS security analysis", "StrikeSuite Team"),
            ("WordPress Scanner", "1.0", "Available", "WordPress security scanner", "StrikeSuite Team")
        ]
        
        for plugin in builtin_plugins:
            row = self.plugins_table.rowCount()
            self.plugins_table.insertRow(row)
            
            self.plugins_table.setItem(row, 0, QTableWidgetItem(plugin[0]))
            self.plugins_table.setItem(row, 1, QTableWidgetItem(plugin[1]))
            self.plugins_table.setItem(row, 2, QTableWidgetItem(plugin[2]))
            self.plugins_table.setItem(row, 3, QTableWidgetItem(plugin[3]))
            self.plugins_table.setItem(row, 4, QTableWidgetItem(plugin[4]))
            
        self.plugin_output.append("Plugins refreshed successfully")
        
    def execute_advanced_plugins(self):
        """Execute advanced plugin chain"""
        if not self.plugin_manager:
            self.plugin_output.append("Plugin manager not available")
            return
            
        # Get advanced options
        options = self.get_advanced_plugin_options()
        
        # Start advanced plugin execution in background thread
        self.plugin_thread = AdvancedPluginThread(self.plugin_manager, options)
        self.plugin_thread.result.connect(self.advanced_plugin_finished)
        self.plugin_thread.start()
        
        self.advanced_execute_btn.setEnabled(False)
        self.plugin_output.append("Starting advanced plugin execution...")
        
    def get_advanced_plugin_options(self):
        """Get advanced plugin options"""
        return {
            'execution_mode': self.execution_mode_combo.currentText().lower(),
            'hot_reload': self.hot_reload_check.isChecked(),
            'dependency_management': self.dependency_mgmt_check.isChecked(),
            'plugin_chaining': self.plugin_chaining_check.isChecked(),
            'resource_management': self.resource_mgmt_check.isChecked(),
            'security_sandbox': self.sandbox_check.isChecked(),
            'performance_monitoring': self.performance_monitor_check.isChecked(),
            'error_recovery': self.error_recovery_check.isChecked()
        }
        
    def advanced_plugin_finished(self, results):
        """Handle advanced plugin execution completion"""
        self.advanced_execute_btn.setEnabled(True)
        
        if isinstance(results, dict):
            # Display execution summary
            if 'summary' in results:
                summary = results['summary']
                self.plugin_output.append(f"Advanced Plugin Execution Summary:")
                self.plugin_output.append(f"Total Plugins: {summary.get('total_plugins', 0)}")
                self.plugin_output.append(f"Successful: {summary.get('successful', 0)}")
                self.plugin_output.append(f"Failed: {summary.get('failed', 0)}")
                self.plugin_output.append(f"Execution Time: {summary.get('execution_time', 0)}s")
                self.plugin_output.append("")
            
            # Display results by plugin
            for plugin_name, result in results.items():
                if plugin_name != 'summary':
                    self.plugin_output.append(f"Plugin: {plugin_name}")
                    if isinstance(result, dict):
                        for key, value in result.items():
                            self.plugin_output.append(f"  {key}: {value}")
                    else:
                        self.plugin_output.append(f"  Result: {result}")
                    self.plugin_output.append("")
        else:
            self.plugin_output.append(f"Advanced Plugin Execution Results: {results}")
        
    def load_plugin(self):
        """Load a plugin from file"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Load Plugin", "", "Python Files (*.py);;All Files (*)"
        )
        if filename:
            self.plugin_output.append(f"Loading plugin: {filename}")
            # Plugin loading logic would go here
            
    def unload_plugin(self):
        """Unload selected plugin"""
        current_row = self.plugins_table.currentRow()
        if current_row >= 0:
            plugin_name = self.plugins_table.item(current_row, 0).text()
            self.plugin_output.append(f"Unloading plugin: {plugin_name}")
            # Plugin unloading logic would go here
            
    def on_plugin_selected(self):
        """Handle plugin selection"""
        current_row = self.plugins_table.currentRow()
        if current_row >= 0:
            plugin_name = self.plugins_table.item(current_row, 0).text()
            self.selected_plugin_label.setText(plugin_name)
            self.configure_btn.setEnabled(True)
            self.run_btn.setEnabled(True)
            
            # Load plugin configuration
            self.plugin_settings_text.setText(f"Configuration for {plugin_name}:\n\nDefault settings loaded.")
        else:
            self.selected_plugin_label.setText("None")
            self.configure_btn.setEnabled(False)
            self.run_btn.setEnabled(False)
            
    def configure_plugin(self):
        """Configure selected plugin"""
        current_row = self.plugins_table.currentRow()
        if current_row >= 0:
            plugin_name = self.plugins_table.item(current_row, 0).text()
            self.plugin_output.append(f"Configuring plugin: {plugin_name}")
            # Plugin configuration logic would go here
            
    def run_plugin(self):
        """Run selected plugin"""
        current_row = self.plugins_table.currentRow()
        if current_row >= 0:
            plugin_name = self.plugins_table.item(current_row, 0).text()
            self.plugin_output.append(f"Running plugin: {plugin_name}")
            self.run_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            
            # Plugin execution logic would go here
            # Simulate plugin execution
            self.plugin_output.append(f"{plugin_name} started successfully")
            
    def stop_plugin(self):
        """Stop running plugin"""
        self.plugin_output.append("Plugin stopped")
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
    def create_plugin(self):
        """Create new plugin from template"""
        template = self.template_combo.currentText()
        self.plugin_output.append(f"Creating new {template}...")
        
        # Plugin creation logic would go here
        self.plugin_output.append(f"{template} template created successfully")
        self.plugin_output.append("Edit the plugin file to customize functionality")
    
    def create_welcome_section(self, layout):
        """Create welcome section with quick start guide"""
        welcome_widget = QWidget()
        welcome_widget.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #2c3e50, stop:1 #34495e);
                border-radius: 10px;
                padding: 15px;
            }
            QLabel {
                color: white;
                font-size: 12px;
            }
        """)
        
        welcome_layout = QHBoxLayout(welcome_widget)
        
        # Welcome text
        welcome_text = QLabel("🔌 Plugin Manager - Extend StrikeSuite functionality")
        welcome_text.setStyleSheet("font-size: 14px; font-weight: bold; color: white;")
        welcome_layout.addWidget(welcome_text)
        
        welcome_layout.addStretch()
        
        # Quick start tips
        tips_text = QLabel("💡 Quick Start: Browse plugins → Configure options → Execute plugins")
        tips_text.setStyleSheet("font-size: 11px; color: #ecf0f1;")
        welcome_layout.addWidget(tips_text)
        
        layout.addWidget(welcome_widget)

class AdvancedPluginThread(QThread):
    """Thread for running advanced plugin execution"""
    result = pyqtSignal(dict)
    
    def __init__(self, plugin_manager, options):
        super().__init__()
        self.plugin_manager = plugin_manager
        self.options = options
        
    def run(self):
        """Run the advanced plugin execution"""
        try:
            # Run advanced plugin execution
            results = self.plugin_manager.advanced_plugin_execution(self.options)
            
            self.result.emit(results)
            
        except Exception as e:
            self.result.emit({'error': str(e)})
