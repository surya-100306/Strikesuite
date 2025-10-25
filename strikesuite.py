#!/usr/bin/env python3
"""
StrikeSuite - Advanced Cybersecurity Testing Framework
A comprehensive security testing platform with GUI interface

This is the legacy entry point. For new installations, use:
python -m strikesuite.main
"""

import sys
import os
import logging
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import from new package structure
try:
    from strikesuite.main import main
except ImportError:
    # Fallback to old structure
    print("⚠️ Using legacy entry point. Consider using: python -m strikesuite.main")

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
    """Main application entry point with enhanced user experience"""
    # Setup logging
    setup_logging()
    logger = logging.getLogger(__name__)
    
    # Display welcome message
    print(">>> StrikeSuite v1.0 - Advanced Penetration Testing Toolkit")
    print("=" * 60)
    print("[INFO] Initializing system...")
    
    try:
        # Check if PyQt5 is available
        try:
            from PyQt5.QtWidgets import QApplication, QSplashScreen, QLabel
            from PyQt5.QtCore import Qt, QTimer
            from PyQt5.QtGui import QPixmap, QFont
            
            print("[OK] PyQt5 detected - Starting GUI mode...")
            
            # Create Qt application first
            app = QApplication(sys.argv)
            app.setApplicationName("StrikeSuite")
            app.setApplicationVersion("1.0.0")
            
            # Create splash screen
            splash = QSplashScreen()
            splash.setPixmap(QPixmap(400, 300))
            splash.show()
            splash.showMessage("Initializing StrikeSuite...", Qt.AlignBottom | Qt.AlignCenter)
            app.processEvents()
            
            # Initialize database with progress
            splash.showMessage("Setting up database...", Qt.AlignBottom | Qt.AlignCenter)
            app.processEvents()
            
            from strikesuite.utils.db_utils import init_db
            init_db()
            print("[OK] Database initialized")
            
            # Initialize plugin manager with progress
            splash.showMessage("Loading plugins...", Qt.AlignBottom | Qt.AlignCenter)
            app.processEvents()
            
            from strikesuite.core.plugin_manager import PluginManager
            plugin_manager = PluginManager()
            plugins = plugin_manager.load_plugins()
            print(f"[OK] Loaded {len(plugins)} plugins")
            
            # Import GUI components
            splash.showMessage("Loading interface...", Qt.AlignBottom | Qt.AlignCenter)
            app.processEvents()
            
            from strikesuite.gui.main_window import MainWindow
            
            # Create and show main window
            splash.showMessage("Starting application...", Qt.AlignBottom | Qt.AlignCenter)
            app.processEvents()
            
            main_window = MainWindow(plugin_manager)
            
            # Close splash screen and show main window
            splash.finish(main_window)
            main_window.show()
            
            # Display success message
            print("[OK] StrikeSuite GUI started successfully")
            print("[TARGET] Ready for penetration testing!")
            print("=" * 60)
            
            logger.info("StrikeSuite GUI started successfully")
            
            # Start event loop
            sys.exit(app.exec_())
            
        except ImportError as e:
            logger.error(f"PyQt5 not available: {e}")
            print("[FAIL] PyQt5 is not installed!")
            print()
            print("[INFO] To install PyQt5, run:")
            print("   pip install PyQt5")
            print()
            print("[CLI] Alternatively, use the CLI version:")
            print("   python strikesuite_cli.py --help")
            print()
            print("[DOCS] For more help, see the documentation in the 'docs' folder")
            sys.exit(1)
        
    except Exception as e:
        logger.error(f"Failed to start StrikeSuite: {e}")
        print(f"[FAIL] Error: {e}")
        print()
        print("[INFO] Troubleshooting:")
        print("   1. Check if all dependencies are installed")
        print("   2. Verify Python version (3.8+ required)")
        print("   3. Check file permissions")
        print("   4. Review error logs in logs/ directory")
        print()
        print("📞 For support, check the documentation or report issues")
        sys.exit(1)

if __name__ == "__main__":
    main()
