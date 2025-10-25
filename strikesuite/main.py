#!/usr/bin/env python3
"""
StrikeSuite Main Entry Point
Advanced Cybersecurity Testing Framework
"""

import sys
import os
import logging
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
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

def check_dependencies():
    """Check if required dependencies are installed"""
    missing_deps = []
    
    try:
        import PyQt5
    except ImportError:
        missing_deps.append("PyQt5")
    
    try:
        import requests
    except ImportError:
        missing_deps.append("requests")
    
    try:
        import paramiko
    except ImportError:
        missing_deps.append("paramiko")
    
    if missing_deps:
        print("❌ Missing dependencies:")
        for dep in missing_deps:
            print(f"   - {dep}")
        print("\n💡 Install missing dependencies with:")
        print("   pip install -r requirements.txt")
        return False
    
    return True

def main():
    """Main application entry point"""
    print("🚀 StrikeSuite v1.0 - Advanced Penetration Testing Toolkit")
    print("=" * 60)
    
    # Setup logging
    setup_logging()
    logger = logging.getLogger(__name__)
    
    try:
        # Check dependencies
        if not check_dependencies():
            return 1
        
        logger.info("StrikeSuite starting...")
        
        # Initialize database
        from strikesuite.utils.db_utils import init_db
        init_db()
        logger.info("Database initialized")
        
        # Load plugins
        from strikesuite.core.plugin_manager import PluginManager
        plugin_manager = PluginManager()
        plugins = plugin_manager.load_plugins()
        logger.info(f"Loaded {len(plugins)} plugins")
        
        # Check for GUI mode
        if len(sys.argv) > 1 and sys.argv[1] == '--cli':
            # CLI mode
            from strikesuite.cli import main as cli_main
            return cli_main()
        else:
            # GUI mode
            from PyQt5.QtWidgets import QApplication
            from strikesuite.gui.main_window import MainWindow
            
            app = QApplication(sys.argv)
            app.setApplicationName("StrikeSuite")
            app.setApplicationVersion("1.0.0")
            
            window = MainWindow(plugin_manager)
            window.show()
            
            logger.info("StrikeSuite GUI started successfully")
            print("[OK] StrikeSuite GUI started successfully")
            print("[TARGET] Ready for penetration testing!")
            print("=" * 60)
            
            return app.exec_()
            
    except Exception as e:
        logger.error(f"Failed to start StrikeSuite: {e}")
        print(f"❌ Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())

