#!/usr/bin/env python3
"""
StrikeSuite - Advanced Cybersecurity Testing Framework
A comprehensive security testing platform with GUI interface
"""

import sys
import os
import logging
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def setup_logging():
    """Configure application logging"""
    log_dir = project_root / "logs"
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / "application.log"),
            logging.StreamHandler()
        ]
    )

def main():
    """Main application entry point"""
    # Setup logging
    setup_logging()
    logger = logging.getLogger(__name__)
    
    try:
        # Check if PyQt5 is available
        try:
            from PyQt5.QtWidgets import QApplication
            from PyQt5.QtCore import Qt
            
            # Create Qt application first
            app = QApplication(sys.argv)
            app.setApplicationName("StrikeSuite")
            app.setApplicationVersion("1.0.0")
            
            # Now import GUI components after QApplication is created
            from gui.main_window import MainWindow
            from core.plugin_manager import PluginManager
            from utils.db_utils import init_db
            
            # Initialize database
            init_db()
            
            # Initialize plugin manager
            plugin_manager = PluginManager()
            plugin_manager.load_plugins()
            
            # Create and show main window
            main_window = MainWindow(plugin_manager)
            main_window.show()
            
            logger.info("StrikeSuite GUI started successfully")
            
            # Start event loop
            sys.exit(app.exec_())
            
        except ImportError as e:
            logger.error(f"PyQt5 not available: {e}")
            print("StrikeSuite v1.0 - Advanced Penetration Testing Toolkit")
            print("=" * 60)
            print("ERROR: PyQt5 is not installed!")
            print("Please install PyQt5 to use the GUI version:")
            print("pip install PyQt5")
            print()
            print("Alternatively, use the CLI version:")
            print("python strikesuite_cli.py --help")
            sys.exit(1)
        
    except Exception as e:
        logger.error(f"Failed to start StrikeSuite: {e}")
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
