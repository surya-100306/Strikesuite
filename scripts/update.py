#!/usr/bin/env python3
"""
StrikeSuite Update Script
Updates the application and dependencies
"""

import sys
import os
import subprocess
import json
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("Error: Python 3.8+ is required")
        sys.exit(1)
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor} detected")

def update_dependencies():
    """Update Python dependencies"""
    print("Updating dependencies...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "-r", "requirements.txt"], 
                      check=True)
        print("✓ Dependencies updated successfully")
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to update dependencies: {e}")
        return False
    return True

def update_database():
    """Update database schema if needed"""
    print("Updating database...")
    try:
        from utils.db_utils import init_db
        init_db()
        print("✓ Database updated successfully")
    except Exception as e:
        print(f"✗ Failed to update database: {e}")
        return False
    return True

def backup_config():
    """Backup current configuration"""
    print("Backing up configuration...")
    config_files = [
        "config/settings.json",
        "config/api_config.json",
        "config/scan_profiles.json",
        "config/database_config.json"
    ]
    
    backup_dir = Path("backups")
    backup_dir.mkdir(exist_ok=True)
    
    for config_file in config_files:
        if os.path.exists(config_file):
            backup_file = backup_dir / f"{Path(config_file).name}.backup"
            try:
                import shutil
                shutil.copy2(config_file, backup_file)
                print(f"✓ Backed up {config_file}")
            except Exception as e:
                print(f"✗ Failed to backup {config_file}: {e}")

def main():
    """Main update function"""
    print("StrikeSuite v1.0 - Update Script")
    print("=" * 40)
    
    # Check Python version
    check_python_version()
    
    # Backup configuration
    backup_config()
    
    # Update dependencies
    if not update_dependencies():
        print("Update failed at dependency stage")
        sys.exit(1)
    
    # Update database
    if not update_database():
        print("Update failed at database stage")
        sys.exit(1)
    
    print("\n" + "=" * 40)
    print("Update completed successfully!")
    print("You can now run StrikeSuite with: python strikesuite.py")

if __name__ == "__main__":
    main()
