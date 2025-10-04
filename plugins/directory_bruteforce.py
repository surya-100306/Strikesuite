#!/usr/bin/env python3
"""
Directory Brute Force Plugin
Web directory and file enumeration
"""

import requests
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict

class DirectoryBruteforce:
    """Directory brute force plugin"""
    
    def __init__(self):
        self.name = "Directory Brute Force"
        self.version = "1.0.0"
        self.description = "Web directory and file enumeration"
        self.author = "StrikeSuite Team"
        
        # Common directories to test
        self.common_directories = [
            "admin", "administrator", "login", "wp-admin", "phpmyadmin",
            "test", "backup", "config", "database", "db", "sql",
            "uploads", "files", "images", "css", "js", "assets",
            "api", "v1", "v2", "docs", "documentation", "help",
            "support", "contact", "about", "news", "blog", "forum"
        ]
        
        # Common files to test
        self.common_files = [
            "index.php", "index.html", "login.php", "admin.php",
            "config.php", "database.php", "backup.sql", "test.php",
            "info.php", "phpinfo.php", "readme.txt", "robots.txt",
            "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml"
        ]
    
    def get_info(self):
        """Return plugin information"""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author
        }
    
    def execute(self, target, options=None):
        """Execute the plugin"""
        if options is None:
            options = {}
        return self.run_bruteforce(target, options)
    
    def validate_target(self, target):
        """Validate target"""
        return target.startswith(('http://', 'https://'))
    
    def get_requirements(self):
        """Return required dependencies"""
        return ['requests']
    
    def check_directory(self, base_url: str, directory: str, timeout: int = 5) -> Dict:
        """Check if a directory exists"""
        url = f"{base_url.rstrip('/')}/{directory}"
        
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=False)
            
            return {
                "url": url,
                "status_code": response.status_code,
                "exists": response.status_code == 200,
                "size": len(response.content),
                "headers": dict(response.headers)
            }
        except Exception as e:
            return {
                "url": url,
                "error": str(e),
                "exists": False
            }
    
    def check_file(self, base_url: str, filename: str, timeout: int = 5) -> Dict:
        """Check if a file exists"""
        url = f"{base_url.rstrip('/')}/{filename}"
        
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=False)
            
            return {
                "url": url,
                "status_code": response.status_code,
                "exists": response.status_code == 200,
                "size": len(response.content),
                "content_type": response.headers.get('content-type', ''),
                "headers": dict(response.headers)
            }
        except Exception as e:
            return {
                "url": url,
                "error": str(e),
                "exists": False
            }
    
    def brute_force_directories(self, base_url: str, directories: List[str] = None, 
                              threads: int = 20) -> List[Dict]:
        """Brute force directory enumeration"""
        if directories is None:
            directories = self.common_directories
        
        results = []
        
        def check_dir(directory):
            result = self.check_directory(base_url, directory)
            if result.get("exists", False):
                results.append(result)
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(check_dir, directories)
        
        return results
    
    def brute_force_files(self, base_url: str, files: List[str] = None, 
                         threads: int = 20) -> List[Dict]:
        """Brute force file enumeration"""
        if files is None:
            files = self.common_files
        
        results = []
        
        def check_file(filename):
            result = self.check_file(base_url, filename)
            if result.get("exists", False):
                results.append(result)
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(check_file, files)
        
        return results
    
    def full_enumeration(self, base_url: str, custom_wordlist: List[str] = None) -> Dict:
        """Perform full directory and file enumeration"""
        results = {
            "target": base_url,
            "directories": [],
            "files": [],
            "summary": {}
        }
        
        # Directory enumeration
        dir_results = self.brute_force_directories(base_url, custom_wordlist)
        results["directories"] = dir_results
        
        # File enumeration
        file_results = self.brute_force_files(base_url)
        results["files"] = file_results
        
        # Summary
        results["summary"] = {
            "directories_found": len(dir_results),
            "files_found": len(file_results),
            "total_findings": len(dir_results) + len(file_results)
        }
        
        return results

# Plugin instance
plugin = DirectoryBruteforce()
