#!/usr/bin/env python3
"""
StrikeSuite Cleanup Script
Cleans up temporary files and old data
"""

import os
import shutil
from pathlib import Path
from datetime import datetime, timedelta

def cleanup_logs(days_old=30):
    """Clean up old log files"""
    print("Cleaning up old log files...")
    
    log_dirs = [
        "logs/scan_logs",
        "logs/api_logs",
        "logs/error_logs"
    ]
    
    cutoff_date = datetime.now() - timedelta(days=days_old)
    cleaned_files = 0
    
    for log_dir in log_dirs:
        if os.path.exists(log_dir):
            for file_path in Path(log_dir).rglob("*"):
                if file_path.is_file():
                    file_time = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if file_time < cutoff_date:
                        try:
                            file_path.unlink()
                            cleaned_files += 1
                            print(f"✓ Removed old log: {file_path}")
                        except Exception as e:
                            print(f"✗ Failed to remove {file_path}: {e}")
    
    print(f"Cleaned up {cleaned_files} old log files")
    return cleaned_files

def cleanup_reports(days_old=90):
    """Clean up old generated reports"""
    print("Cleaning up old reports...")
    
    reports_dir = "reports/generated"
    if not os.path.exists(reports_dir):
        print("No reports directory found")
        return 0
    
    cutoff_date = datetime.now() - timedelta(days=days_old)
    cleaned_files = 0
    
    for file_path in Path(reports_dir).rglob("*"):
        if file_path.is_file():
            file_time = datetime.fromtimestamp(file_path.stat().st_mtime)
            if file_time < cutoff_date:
                try:
                    file_path.unlink()
                    cleaned_files += 1
                    print(f"✓ Removed old report: {file_path}")
                except Exception as e:
                    print(f"✗ Failed to remove {file_path}: {e}")
    
    print(f"Cleaned up {cleaned_files} old reports")
    return cleaned_files

def cleanup_temp_files():
    """Clean up temporary files"""
    print("Cleaning up temporary files...")
    
    temp_patterns = [
        "*.tmp",
        "*.temp", 
        "*.log",
        "__pycache__",
        "*.pyc",
        "*.pyo"
    ]
    
    cleaned_files = 0
    
    for pattern in temp_patterns:
        for file_path in Path(".").rglob(pattern):
            if file_path.is_file():
                try:
                    file_path.unlink()
                    cleaned_files += 1
                    print(f"✓ Removed temp file: {file_path}")
                except Exception as e:
                    print(f"✗ Failed to remove {file_path}: {e}")
            elif file_path.is_dir() and pattern == "__pycache__":
                try:
                    shutil.rmtree(file_path)
                    cleaned_files += 1
                    print(f"✓ Removed temp directory: {file_path}")
                except Exception as e:
                    print(f"✗ Failed to remove {file_path}: {e}")
    
    print(f"Cleaned up {cleaned_files} temporary files")
    return cleaned_files

def cleanup_database_old_records(days_old=365):
    """Clean up old database records"""
    print("Cleaning up old database records...")
    
    try:
        from utils.db_utils import DatabaseUtils
        
        db_manager = DatabaseUtils()
        db_manager.connect()
        
        # Clean up old scan history
        cutoff_date = datetime.now() - timedelta(days=days_old)
        deleted_count = db_manager.cleanup_old_data(cutoff_date)
        
        db_manager.disconnect()
        
        print(f"Cleaned up {deleted_count} old database records")
        return deleted_count
        
    except Exception as e:
        print(f"✗ Failed to cleanup database: {e}")
        return 0

def cleanup_backups(days_old=30):
    """Clean up old backup files"""
    print("Cleaning up old backups...")
    
    backups_dir = "backups"
    if not os.path.exists(backups_dir):
        print("No backups directory found")
        return 0
    
    cutoff_date = datetime.now() - timedelta(days=days_old)
    cleaned_files = 0
    
    for backup_path in Path(backups_dir).iterdir():
        if backup_path.is_dir():
            backup_time = datetime.fromtimestamp(backup_path.stat().st_mtime)
            if backup_time < cutoff_date:
                try:
                    shutil.rmtree(backup_path)
                    cleaned_files += 1
                    print(f"✓ Removed old backup: {backup_path}")
                except Exception as e:
                    print(f"✗ Failed to remove {backup_path}: {e}")
    
    print(f"Cleaned up {cleaned_files} old backups")
    return cleaned_files

def get_disk_usage():
    """Get current disk usage"""
    total_size = 0
    
    for file_path in Path(".").rglob("*"):
        if file_path.is_file():
            total_size += file_path.stat().st_size
    
    return total_size / (1024 * 1024)  # Convert to MB

def main():
    """Main cleanup function"""
    print("StrikeSuite v1.0 - Cleanup Script")
    print("=" * 40)
    
    # Get initial disk usage
    initial_size = get_disk_usage()
    print(f"Initial disk usage: {initial_size:.2f} MB")
    
    # Clean up various file types
    log_files = cleanup_logs()
    report_files = cleanup_reports()
    temp_files = cleanup_temp_files()
    db_records = cleanup_database_old_records()
    backup_files = cleanup_backups()
    
    # Get final disk usage
    final_size = get_disk_usage()
    freed_space = initial_size - final_size
    
    print("\n" + "=" * 40)
    print("Cleanup completed!")
    print(f"Files cleaned up: {log_files + report_files + temp_files + backup_files}")
    print(f"Database records cleaned: {db_records}")
    print(f"Space freed: {freed_space:.2f} MB")
    print(f"Current disk usage: {final_size:.2f} MB")

if __name__ == "__main__":
    main()
