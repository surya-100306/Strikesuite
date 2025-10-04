#!/usr/bin/env python3
"""
StrikeSuite Configuration Backup Script
Backs up configuration files and settings
"""

import os
import shutil
import json
from datetime import datetime
from pathlib import Path

def create_backup_directory():
    """Create backup directory with timestamp"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = Path(f"backups/config_backup_{timestamp}")
    backup_dir.mkdir(parents=True, exist_ok=True)
    return backup_dir

def backup_config_files(backup_dir):
    """Backup configuration files"""
    config_files = [
        "config/settings.json",
        "config/api_config.json", 
        "config/scan_profiles.json",
        "config/database_config.json"
    ]
    
    backed_up = []
    
    for config_file in config_files:
        if os.path.exists(config_file):
            try:
                shutil.copy2(config_file, backup_dir / Path(config_file).name)
                backed_up.append(config_file)
                print(f"✓ Backed up {config_file}")
            except Exception as e:
                print(f"✗ Failed to backup {config_file}: {e}")
        else:
            print(f"⚠ {config_file} not found")
    
    return backed_up

def backup_database_files(backup_dir):
    """Backup database files"""
    db_files = [
        "database/strikesuite.db",
        "database/vulnerabilities.db",
        "database/cve_data.db",
        "database/scan_history.db"
    ]
    
    db_backup_dir = backup_dir / "database"
    db_backup_dir.mkdir(exist_ok=True)
    
    backed_up = []
    
    for db_file in db_files:
        if os.path.exists(db_file):
            try:
                shutil.copy2(db_file, db_backup_dir / Path(db_file).name)
                backed_up.append(db_file)
                print(f"✓ Backed up {db_file}")
            except Exception as e:
                print(f"✗ Failed to backup {db_file}: {e}")
        else:
            print(f"⚠ {db_file} not found")
    
    return backed_up

def backup_logs(backup_dir):
    """Backup log files"""
    log_dirs = [
        "logs/scan_logs",
        "logs/api_logs", 
        "logs/error_logs"
    ]
    
    logs_backup_dir = backup_dir / "logs"
    logs_backup_dir.mkdir(exist_ok=True)
    
    backed_up = []
    
    for log_dir in log_dirs:
        if os.path.exists(log_dir):
            try:
                shutil.copytree(log_dir, logs_backup_dir / Path(log_dir).name)
                backed_up.append(log_dir)
                print(f"✓ Backed up {log_dir}")
            except Exception as e:
                print(f"✗ Failed to backup {log_dir}: {e}")
        else:
            print(f"⚠ {log_dir} not found")
    
    return backed_up

def create_backup_info(backup_dir, config_files, db_files, log_dirs):
    """Create backup information file"""
    backup_info = {
        "timestamp": datetime.now().isoformat(),
        "backup_type": "configuration",
        "files_backed_up": {
            "config_files": config_files,
            "database_files": db_files,
            "log_directories": log_dirs
        },
        "total_files": len(config_files) + len(db_files) + len(log_dirs)
    }
    
    try:
        with open(backup_dir / "backup_info.json", "w") as f:
            json.dump(backup_info, f, indent=2)
        print("✓ Created backup information file")
    except Exception as e:
        print(f"✗ Failed to create backup info: {e}")

def main():
    """Main backup function"""
    print("StrikeSuite v1.0 - Configuration Backup")
    print("=" * 40)
    
    # Create backup directory
    backup_dir = create_backup_directory()
    print(f"Backup directory: {backup_dir}")
    
    # Backup configuration files
    print("\nBacking up configuration files...")
    config_files = backup_config_files(backup_dir)
    
    # Backup database files
    print("\nBacking up database files...")
    db_files = backup_database_files(backup_dir)
    
    # Backup log files
    print("\nBacking up log files...")
    log_dirs = backup_logs(backup_dir)
    
    # Create backup information
    create_backup_info(backup_dir, config_files, db_files, log_dirs)
    
    print("\n" + "=" * 40)
    print("Backup completed successfully!")
    print(f"Backup location: {backup_dir}")
    print(f"Total files backed up: {len(config_files) + len(db_files) + len(log_dirs)}")

if __name__ == "__main__":
    main()
