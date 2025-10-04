#!/usr/bin/env python3
"""
WordPress Security Scanner Plugin
Comprehensive WordPress security assessment
"""

import requests
import re
from typing import Dict, List
from urllib.parse import urljoin

class WordPressScanner:
    """WordPress security scanner plugin"""
    
    def __init__(self):
        self.name = "WordPress Security Scanner"
        self.version = "1.0.0"
        self.description = "Comprehensive WordPress security assessment"
        self.author = "StrikeSuite Team"
        
        # Common WordPress files and directories
        self.wp_files = [
            "wp-config.php",
            "wp-admin/",
            "wp-content/",
            "wp-includes/",
            "xmlrpc.php",
            "wp-login.php",
            "wp-cron.php",
            "readme.html",
            "license.txt"
        ]
        
        # Common WordPress vulnerabilities
        self.vulnerabilities = {
            "version_disclosure": self.check_version_disclosure,
            "directory_listing": self.check_directory_listing,
            "xmlrpc_enabled": self.check_xmlrpc,
            "file_upload": self.check_file_upload,
            "user_enumeration": self.check_user_enumeration,
            "weak_passwords": self.check_weak_passwords
        }
    
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
        return self.scan_wordpress(target, options)
    
    def validate_target(self, target):
        """Validate target"""
        return target.startswith(('http://', 'https://'))
    
    def get_requirements(self):
        """Return required dependencies"""
        return ['requests']
    
    def is_wordpress_site(self, base_url: str) -> bool:
        """Check if the site is running WordPress"""
        try:
            response = requests.get(base_url, timeout=10)
            content = response.text.lower()
            
            # Check for WordPress indicators
            wp_indicators = [
                "wp-content",
                "wp-includes", 
                "wordpress",
                "wp-admin"
            ]
            
            return any(indicator in content for indicator in wp_indicators)
        except:
            return False
    
    def get_wordpress_version(self, base_url: str) -> str:
        """Get WordPress version"""
        try:
            # Check readme.html
            response = requests.get(urljoin(base_url, "readme.html"), timeout=10)
            if response.status_code == 200:
                version_match = re.search(r'Version (\d+\.\d+(?:\.\d+)?)', response.text)
                if version_match:
                    return version_match.group(1)
            
            # Check generator meta tag
            response = requests.get(base_url, timeout=10)
            if response.status_code == 200:
                generator_match = re.search(r'<meta name="generator" content="WordPress (\d+\.\d+(?:\.\d+)?)"', response.text)
                if generator_match:
                    return generator_match.group(1)
            
            return "Unknown"
        except:
            return "Unknown"
    
    def check_version_disclosure(self, base_url: str) -> Dict:
        """Check for version disclosure"""
        results = {
            "vulnerability": "Version Disclosure",
            "found": False,
            "version": None,
            "details": []
        }
        
        version = self.get_wordpress_version(base_url)
        if version != "Unknown":
            results["found"] = True
            results["version"] = version
            results["details"].append(f"WordPress version {version} disclosed")
        
        return results
    
    def check_directory_listing(self, base_url: str) -> Dict:
        """Check for directory listing vulnerabilities"""
        results = {
            "vulnerability": "Directory Listing",
            "found": False,
            "exposed_directories": []
        }
        
        # Check common WordPress directories
        directories_to_check = [
            "wp-content/uploads/",
            "wp-content/themes/",
            "wp-content/plugins/",
            "wp-includes/"
        ]
        
        for directory in directories_to_check:
            try:
                response = requests.get(urljoin(base_url, directory), timeout=10)
                if response.status_code == 200 and "Index of" in response.text:
                    results["found"] = True
                    results["exposed_directories"].append(directory)
            except:
                pass
        
        return results
    
    def check_xmlrpc(self, base_url: str) -> Dict:
        """Check if XML-RPC is enabled"""
        results = {
            "vulnerability": "XML-RPC Enabled",
            "found": False,
            "details": []
        }
        
        try:
            response = requests.get(urljoin(base_url, "xmlrpc.php"), timeout=10)
            if response.status_code == 200 and "XML-RPC" in response.text:
                results["found"] = True
                results["details"].append("XML-RPC is enabled and accessible")
        except:
            pass
        
        return results
    
    def check_file_upload(self, base_url: str) -> Dict:
        """Check for file upload vulnerabilities"""
        results = {
            "vulnerability": "File Upload",
            "found": False,
            "details": []
        }
        
        # Check for common file upload endpoints
        upload_endpoints = [
            "wp-admin/async-upload.php",
            "wp-content/uploads/",
            "wp-admin/media-upload.php"
        ]
        
        for endpoint in upload_endpoints:
            try:
                response = requests.get(urljoin(base_url, endpoint), timeout=10)
                if response.status_code == 200:
                    results["found"] = True
                    results["details"].append(f"Upload endpoint accessible: {endpoint}")
            except:
                pass
        
        return results
    
    def check_user_enumeration(self, base_url: str) -> Dict:
        """Check for user enumeration vulnerabilities"""
        results = {
            "vulnerability": "User Enumeration",
            "found": False,
            "users": []
        }
        
        # Try to enumerate users
        for user_id in range(1, 10):
            try:
                response = requests.get(urljoin(base_url, f"?author={user_id}"), timeout=10)
                if response.status_code == 200 and "author" in response.url:
                    results["found"] = True
                    results["users"].append(f"User ID {user_id}")
            except:
                pass
        
        return results
    
    def check_weak_passwords(self, base_url: str) -> Dict:
        """Check for weak password policies"""
        results = {
            "vulnerability": "Weak Password Policy",
            "found": False,
            "details": []
        }
        
        # This would require actual login attempts
        # For now, just check if login page exists
        try:
            response = requests.get(urljoin(base_url, "wp-login.php"), timeout=10)
            if response.status_code == 200:
                results["found"] = True
                results["details"].append("Login page accessible")
        except:
            pass
        
        return results
    
    def scan_wordpress(self, base_url: str) -> Dict:
        """Perform comprehensive WordPress security scan"""
        results = {
            "target": base_url,
            "is_wordpress": False,
            "version": None,
            "vulnerabilities": [],
            "summary": {}
        }
        
        # Check if it's a WordPress site
        if not self.is_wordpress_site(base_url):
            results["summary"]["message"] = "Not a WordPress site"
            return results
        
        results["is_wordpress"] = True
        results["version"] = self.get_wordpress_version(base_url)
        
        # Run vulnerability checks
        for vuln_name, vuln_func in self.vulnerabilities.items():
            try:
                vuln_result = vuln_func(base_url)
                if vuln_result.get("found", False):
                    results["vulnerabilities"].append(vuln_result)
            except Exception as e:
                results["vulnerabilities"].append({
                    "vulnerability": vuln_name,
                    "error": str(e)
                })
        
        # Summary
        results["summary"] = {
            "total_vulnerabilities": len(results["vulnerabilities"]),
            "high_risk": len([v for v in results["vulnerabilities"] if v.get("found", False)]),
            "version": results["version"]
        }
        
        return results

# Plugin instance
plugin = WordPressScanner()
