#!/usr/bin/env python3
"""
Validation Utilities
Input validation and sanitization
"""

import re
import logging
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

class ValidationUtils:
    """
    Input validation and sanitization utilities
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def validate_ip_address(self, ip: str) -> bool:
        """
        Validate IP address format
        
        Args:
            ip: IP address string
            
        Returns:
            True if valid IP, False otherwise
        """
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def validate_port(self, port: Union[str, int]) -> bool:
        """
        Validate port number
        
        Args:
            port: Port number
            
        Returns:
            True if valid port, False otherwise
        """
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except (ValueError, TypeError):
            return False
    
    def validate_url(self, url: str) -> bool:
        """
        Validate URL format
        
        Args:
            url: URL string
            
        Returns:
            True if valid URL, False otherwise
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def validate_email(self, email: str) -> bool:
        """
        Validate email address format
        
        Args:
            email: Email address string
            
        Returns:
            True if valid email, False otherwise
        """
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def validate_hostname(self, hostname: str) -> bool:
        """
        Validate hostname format
        
        Args:
            hostname: Hostname string
            
        Returns:
            True if valid hostname, False otherwise
        """
        if not hostname or len(hostname) > 253:
            return False
        
        # Check each label
        labels = hostname.split('.')
        for label in labels:
            if not label or len(label) > 63:
                return False
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$', label):
                return False
        
        return True
    
    def sanitize_string(self, text: str, max_length: int = 1000) -> str:
        """
        Sanitize string input
        
        Args:
            text: Input string
            max_length: Maximum string length
            
        Returns:
            Sanitized string
        """
        if not isinstance(text, str):
            return ""
        
        # Remove null bytes and control characters
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
        
        # Limit length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized.strip()
    
    def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename
        
        Args:
            filename: Input filename
            
        Returns:
            Sanitized filename
        """
        if not isinstance(filename, str):
            return "file"
        
        # Remove dangerous characters
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
        
        # Remove leading/trailing dots and spaces
        sanitized = sanitized.strip('. ')
        
        # Ensure it's not empty
        if not sanitized:
            sanitized = "file"
        
        # Limit length
        if len(sanitized) > 255:
            sanitized = sanitized[:255]
        
        return sanitized
    
    def validate_json(self, json_string: str) -> bool:
        """
        Validate JSON string
        
        Args:
            json_string: JSON string to validate
            
        Returns:
            True if valid JSON, False otherwise
        """
        try:
            import json
            json.loads(json_string)
            return True
        except (ValueError, TypeError):
            return False
    
    def validate_scan_config(self, config: Dict) -> Dict[str, List[str]]:
        """
        Validate scan configuration
        
        Args:
            config: Scan configuration dictionary
            
        Returns:
            Dictionary of validation errors
        """
        errors = {}
        
        # Validate target
        if 'target' not in config:
            errors['target'] = ['Target is required']
        else:
            target = config['target']
            if not (self.validate_ip_address(target) or 
                   self.validate_hostname(target) or 
                   self.validate_url(target)):
                errors['target'] = ['Invalid target format']
        
        # Validate ports
        if 'ports' in config:
            ports = config['ports']
            if isinstance(ports, str):
                # Port range or comma-separated
                if '-' in ports:
                    start, end = ports.split('-', 1)
                    if not (self.validate_port(start) and self.validate_port(end)):
                        errors['ports'] = ['Invalid port range']
                elif ',' in ports:
                    for port in ports.split(','):
                        if not self.validate_port(port.strip()):
                            errors['ports'] = ['Invalid port in list']
                            break
                else:
                    if not self.validate_port(ports):
                        errors['ports'] = ['Invalid port']
            elif isinstance(ports, list):
                for port in ports:
                    if not self.validate_port(port):
                        errors['ports'] = ['Invalid port in list']
                        break
        
        # Validate threads
        if 'threads' in config:
            threads = config['threads']
            if not isinstance(threads, int) or threads < 1 or threads > 1000:
                errors['threads'] = ['Threads must be between 1 and 1000']
        
        # Validate timeout
        if 'timeout' in config:
            timeout = config['timeout']
            if not isinstance(timeout, (int, float)) or timeout < 0.1 or timeout > 60:
                errors['timeout'] = ['Timeout must be between 0.1 and 60 seconds']
        
        return errors
    
    def validate_api_config(self, config: Dict) -> Dict[str, List[str]]:
        """
        Validate API configuration
        
        Args:
            config: API configuration dictionary
            
        Returns:
            Dictionary of validation errors
        """
        errors = {}
        
        # Validate base URL
        if 'base_url' not in config:
            errors['base_url'] = ['Base URL is required']
        else:
            if not self.validate_url(config['base_url']):
                errors['base_url'] = ['Invalid base URL format']
        
        # Validate endpoints
        if 'endpoints' in config:
            endpoints = config['endpoints']
            if not isinstance(endpoints, list):
                errors['endpoints'] = ['Endpoints must be a list']
            else:
                for endpoint in endpoints:
                    if not isinstance(endpoint, str) or not endpoint.startswith('/'):
                        errors['endpoints'] = ['Invalid endpoint format']
                        break
        
        # Validate authentication
        if 'auth_type' in config:
            auth_type = config['auth_type']
            valid_auth_types = ['none', 'bearer', 'api_key', 'basic']
            if auth_type not in valid_auth_types:
                errors['auth_type'] = [f'Auth type must be one of: {valid_auth_types}']
        
        return errors
    
    def validate_credentials(self, credentials: Dict) -> Dict[str, List[str]]:
        """
        Validate credentials
        
        Args:
            credentials: Credentials dictionary
            
        Returns:
            Dictionary of validation errors
        """
        errors = {}
        
        # Validate usernames
        if 'usernames' in credentials:
            usernames = credentials['usernames']
            if not isinstance(usernames, list):
                errors['usernames'] = ['Usernames must be a list']
            else:
                for username in usernames:
                    if not isinstance(username, str) or len(username) == 0:
                        errors['usernames'] = ['Invalid username format']
                        break
        
        # Validate passwords
        if 'passwords' in credentials:
            passwords = credentials['passwords']
            if not isinstance(passwords, list):
                errors['passwords'] = ['Passwords must be a list']
            else:
                for password in passwords:
                    if not isinstance(password, str):
                        errors['passwords'] = ['Invalid password format']
                        break
        
        return errors
    
    def sanitize_sql_input(self, input_string: str) -> str:
        """
        Sanitize SQL input to prevent injection
        
        Args:
            input_string: Input string
            
        Returns:
            Sanitized string
        """
        if not isinstance(input_string, str):
            return ""
        
        # Remove SQL injection patterns
        dangerous_patterns = [
            r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)',
            r'(\b(OR|AND)\s+\d+\s*=\s*\d+)',
            r'(\'|\"|;|--|\/\*|\*\/)',
            r'(\b(SCRIPT|JAVASCRIPT|VBSCRIPT)\b)',
            r'(\b(ONLOAD|ONERROR|ONCLICK)\b)'
        ]
        
        sanitized = input_string
        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        return sanitized.strip()
    
    def sanitize_html_input(self, input_string: str) -> str:
        """
        Sanitize HTML input to prevent XSS
        
        Args:
            input_string: Input string
            
        Returns:
            Sanitized string
        """
        if not isinstance(input_string, str):
            return ""
        
        # Remove HTML tags and attributes
        sanitized = re.sub(r'<[^>]+>', '', input_string)
        
        # Remove JavaScript
        sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'on\w+\s*=', '', sanitized, flags=re.IGNORECASE)
        
        # Remove script tags
        sanitized = re.sub(r'<script[^>]*>.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        return sanitized.strip()
    
    def validate_file_path(self, file_path: str) -> bool:
        """
        Validate file path for security
        
        Args:
            file_path: File path to validate
            
        Returns:
            True if valid path, False otherwise
        """
        if not isinstance(file_path, str):
            return False
        
        # Check for directory traversal
        if '..' in file_path or file_path.startswith('/'):
            return False
        
        # Check for dangerous characters
        dangerous_chars = ['<', '>', ':', '"', '|', '?', '*']
        for char in dangerous_chars:
            if char in file_path:
                return False
        
        return True
