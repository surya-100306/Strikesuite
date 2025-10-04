#!/usr/bin/env python3
"""
File Utilities
File handling and management utilities
"""

import os
import json
import shutil
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

class FileUtils:
    """
    File handling and management utilities
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def ensure_directories(self):
        """Ensure all required directories exist"""
        directories = [
            "logs",
            "logs/scan_logs", 
            "logs/api_logs",
            "logs/error_logs",
            "reports",
            "reports/generated",
            "reports/templates",
            "database",
            "config",
            "wordlists",
            "payloads",
            "payloads/reverse_shells",
            "payloads/web_shells", 
            "payloads/privilege_escalation",
            "payloads/privilege_escalation/enum_scripts",
            "plugins",
            "assets",
            "assets/icons",
            "assets/icons/tab_icons",
            "assets/images",
            "assets/sounds"
        ]
        
        for directory in directories:
            try:
                os.makedirs(directory, exist_ok=True)
                self.logger.debug(f"Ensured directory exists: {directory}")
            except Exception as e:
                self.logger.error(f"Failed to create directory {directory}: {e}")
    
    def save_json(self, data: Dict, filepath: str) -> bool:
        """
        Save data to JSON file
        
        Args:
            data: Data to save
            filepath: Path to save file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Saved JSON data to {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save JSON to {filepath}: {e}")
            return False
    
    def load_json(self, filepath: str) -> Optional[Dict]:
        """
        Load data from JSON file
        
        Args:
            filepath: Path to JSON file
            
        Returns:
            Loaded data or None if failed
        """
        try:
            if not os.path.exists(filepath):
                self.logger.warning(f"JSON file not found: {filepath}")
                return None
            
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.logger.debug(f"Loaded JSON data from {filepath}")
            return data
            
        except Exception as e:
            self.logger.error(f"Failed to load JSON from {filepath}: {e}")
            return None
    
    def save_text(self, content: str, filepath: str) -> bool:
        """
        Save text content to file
        
        Args:
            content: Text content to save
            filepath: Path to save file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.logger.info(f"Saved text content to {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save text to {filepath}: {e}")
            return False
    
    def load_text(self, filepath: str) -> Optional[str]:
        """
        Load text content from file
        
        Args:
            filepath: Path to text file
            
        Returns:
            Text content or None if failed
        """
        try:
            if not os.path.exists(filepath):
                self.logger.warning(f"Text file not found: {filepath}")
                return None
            
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.logger.debug(f"Loaded text content from {filepath}")
            return content
            
        except Exception as e:
            self.logger.error(f"Failed to load text from {filepath}: {e}")
            return None
    
    def load_wordlist(self, wordlist_path: str) -> List[str]:
        """
        Load wordlist from file
        
        Args:
            wordlist_path: Path to wordlist file
            
        Returns:
            List of words from wordlist
        """
        try:
            if not os.path.exists(wordlist_path):
                self.logger.warning(f"Wordlist file not found: {wordlist_path}")
                return []
            
            words = []
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word and not word.startswith('#'):
                        words.append(word)
            
            self.logger.info(f"Loaded {len(words)} words from {wordlist_path}")
            return words
            
        except Exception as e:
            self.logger.error(f"Failed to load wordlist from {wordpath}: {e}")
            return []
    
    def get_file_size(self, filepath: str) -> int:
        """
        Get file size in bytes
        
        Args:
            filepath: Path to file
            
        Returns:
            File size in bytes, 0 if file doesn't exist
        """
        try:
            if os.path.exists(filepath):
                return os.path.getsize(filepath)
            return 0
        except Exception as e:
            self.logger.error(f"Failed to get file size for {filepath}: {e}")
            return 0
    
    def get_file_extension(self, filepath: str) -> str:
        """
        Get file extension
        
        Args:
            filepath: Path to file
            
        Returns:
            File extension (without dot)
        """
        try:
            return Path(filepath).suffix.lstrip('.')
        except Exception as e:
            self.logger.error(f"Failed to get file extension for {filepath}: {e}")
            return ""
    
    def copy_file(self, src: str, dst: str) -> bool:
        """
        Copy file from source to destination
        
        Args:
            src: Source file path
            dst: Destination file path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure destination directory exists
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            
            shutil.copy2(src, dst)
            self.logger.info(f"Copied file from {src} to {dst}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to copy file from {src} to {dst}: {e}")
            return False
    
    def move_file(self, src: str, dst: str) -> bool:
        """
        Move file from source to destination
        
        Args:
            src: Source file path
            dst: Destination file path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure destination directory exists
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            
            shutil.move(src, dst)
            self.logger.info(f"Moved file from {src} to {dst}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to move file from {src} to {dst}: {e}")
            return False
    
    def delete_file(self, filepath: str) -> bool:
        """
        Delete file
        
        Args:
            filepath: Path to file to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
                self.logger.info(f"Deleted file {filepath}")
                return True
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to delete file {filepath}: {e}")
            return False
    
    def list_files(self, directory: str, pattern: str = "*") -> List[str]:
        """
        List files in directory matching pattern
        
        Args:
            directory: Directory to list files from
            pattern: File pattern to match
            
        Returns:
            List of file paths
        """
        try:
            if not os.path.exists(directory):
                return []
            
            files = []
            for root, dirs, filenames in os.walk(directory):
                for filename in filenames:
                    if pattern == "*" or filename.endswith(pattern):
                        files.append(os.path.join(root, filename))
            
            return files
            
        except Exception as e:
            self.logger.error(f"Failed to list files in {directory}: {e}")
            return []
    
    def create_backup(self, filepath: str) -> Optional[str]:
        """
        Create backup of file
        
        Args:
            filepath: Path to file to backup
            
        Returns:
            Path to backup file or None if failed
        """
        try:
            if not os.path.exists(filepath):
                return None
            
            import time
            timestamp = int(time.time())
            backup_path = f"{filepath}.backup.{timestamp}"
            
            shutil.copy2(filepath, backup_path)
            self.logger.info(f"Created backup of {filepath} at {backup_path}")
            return backup_path
            
        except Exception as e:
            self.logger.error(f"Failed to create backup of {filepath}: {e}")
            return None
    
    def cleanup_old_files(self, directory: str, max_age_days: int = 30) -> int:
        """
        Clean up old files in directory
        
        Args:
            directory: Directory to clean up
            max_age_days: Maximum age of files in days
            
        Returns:
            Number of files deleted
        """
        try:
            if not os.path.exists(directory):
                return 0
            
            import time
            current_time = time.time()
            max_age_seconds = max_age_days * 24 * 60 * 60
            deleted_count = 0
            
            for root, dirs, filenames in os.walk(directory):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    file_age = current_time - os.path.getmtime(filepath)
                    
                    if file_age > max_age_seconds:
                        try:
                            os.remove(filepath)
                            deleted_count += 1
                            self.logger.debug(f"Deleted old file: {filepath}")
                        except Exception as e:
                            self.logger.error(f"Failed to delete old file {filepath}: {e}")
            
            self.logger.info(f"Cleaned up {deleted_count} old files from {directory}")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old files in {directory}: {e}")
            return 0
