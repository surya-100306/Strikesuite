#!/usr/bin/env python3
"""
Advanced API Security Tester Plugin
Comprehensive API security testing with OWASP Top 10 focus
"""

import requests
import json
import time
from typing import Dict, List, Any
from urllib.parse import urljoin

class AdvancedAPITester:
    """Advanced API security testing plugin"""
    
    def __init__(self):
        self.name = "Advanced API Tester"
        self.version = "1.0.0"
        self.description = "Comprehensive API security testing"
        self.author = "StrikeSuite Team"
        
        # OWASP API Security Top 10 test cases
        self.test_cases = {
            "broken_object_level_authorization": self.test_broken_object_level_authorization,
            "broken_authentication": self.test_broken_authentication,
            "excessive_data_exposure": self.test_excessive_data_exposure,
            "lack_of_rate_limiting": self.test_rate_limiting,
            "broken_function_level_authorization": self.test_broken_function_authorization,
            "mass_assignment": self.test_mass_assignment,
            "security_misconfiguration": self.test_security_misconfiguration,
            "injection": self.test_injection,
            "improper_assets_management": self.test_improper_assets_management,
            "insufficient_logging": self.test_insufficient_logging
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
        return self.run_full_test(target, options.get('headers'))
    
    def validate_target(self, target):
        """Validate target"""
        return target.startswith(('http://', 'https://'))
    
    def get_requirements(self):
        """Return required dependencies"""
        return ['requests']
    
    def test_broken_object_level_authorization(self, base_url: str, headers: Dict = None) -> Dict:
        """Test for broken object level authorization"""
        results = {"vulnerability": "Broken Object Level Authorization", "tests": []}
        
        # Test accessing other users' resources
        test_endpoints = [
            "/api/users/1",
            "/api/users/2", 
            "/api/orders/1",
            "/api/profile/1"
        ]
        
        for endpoint in test_endpoints:
            try:
                response = requests.get(urljoin(base_url, endpoint), headers=headers, timeout=10)
                if response.status_code == 200:
                    results["tests"].append({
                        "endpoint": endpoint,
                        "status": "vulnerable",
                        "response_code": response.status_code
                    })
            except Exception as e:
                results["tests"].append({
                    "endpoint": endpoint,
                    "status": "error",
                    "error": str(e)
                })
        
        return results
    
    def test_broken_authentication(self, base_url: str, headers: Dict = None) -> Dict:
        """Test for broken authentication"""
        results = {"vulnerability": "Broken Authentication", "tests": []}
        
        # Test weak authentication mechanisms
        auth_tests = [
            {"name": "No authentication required", "endpoint": "/api/admin"},
            {"name": "Weak JWT", "endpoint": "/api/verify"},
            {"name": "Session fixation", "endpoint": "/api/session"}
        ]
        
        for test in auth_tests:
            try:
                response = requests.get(urljoin(base_url, test["endpoint"]), headers=headers, timeout=10)
                results["tests"].append({
                    "test": test["name"],
                    "endpoint": test["endpoint"],
                    "status_code": response.status_code,
                    "vulnerable": response.status_code == 200
                })
            except Exception as e:
                results["tests"].append({
                    "test": test["name"],
                    "error": str(e)
                })
        
        return results
    
    def test_excessive_data_exposure(self, base_url: str, headers: Dict = None) -> Dict:
        """Test for excessive data exposure"""
        results = {"vulnerability": "Excessive Data Exposure", "tests": []}
        
        # Test endpoints that might expose sensitive data
        sensitive_endpoints = [
            "/api/users",
            "/api/profile",
            "/api/admin/users"
        ]
        
        for endpoint in sensitive_endpoints:
            try:
                response = requests.get(urljoin(base_url, endpoint), headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
                    # Check for sensitive fields
                    sensitive_fields = ['password', 'ssn', 'credit_card', 'api_key', 'token']
                    exposed_fields = [field for field in sensitive_fields if field in str(data).lower()]
                    
                    results["tests"].append({
                        "endpoint": endpoint,
                        "exposed_fields": exposed_fields,
                        "vulnerable": len(exposed_fields) > 0
                    })
            except Exception as e:
                results["tests"].append({
                    "endpoint": endpoint,
                    "error": str(e)
                })
        
        return results
    
    def test_rate_limiting(self, base_url: str, headers: Dict = None) -> Dict:
        """Test for lack of rate limiting"""
        results = {"vulnerability": "Lack of Rate Limiting", "tests": []}
        
        # Test rate limiting by making multiple requests
        test_endpoint = "/api/login"
        request_count = 100
        successful_requests = 0
        
        for i in range(request_count):
            try:
                response = requests.post(urljoin(base_url, test_endpoint), 
                                       json={"username": "test", "password": "test"}, 
                                       headers=headers, timeout=5)
                if response.status_code not in [429, 503]:  # Not rate limited
                    successful_requests += 1
            except:
                pass
        
        results["tests"].append({
            "endpoint": test_endpoint,
            "total_requests": request_count,
            "successful_requests": successful_requests,
            "rate_limited": successful_requests < request_count
        })
        
        return results
    
    def test_broken_function_authorization(self, base_url: str, headers: Dict = None) -> Dict:
        """Test for broken function level authorization"""
        results = {"vulnerability": "Broken Function Level Authorization", "tests": []}
        
        # Test admin functions without proper authorization
        admin_endpoints = [
            "/api/admin/users",
            "/api/admin/delete",
            "/api/admin/config"
        ]
        
        for endpoint in admin_endpoints:
            try:
                response = requests.get(urljoin(base_url, endpoint), headers=headers, timeout=10)
                results["tests"].append({
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "vulnerable": response.status_code == 200
                })
            except Exception as e:
                results["tests"].append({
                    "endpoint": endpoint,
                    "error": str(e)
                })
        
        return results
    
    def test_mass_assignment(self, base_url: str, headers: Dict = None) -> Dict:
        """Test for mass assignment vulnerabilities"""
        results = {"vulnerability": "Mass Assignment", "tests": []}
        
        # Test mass assignment in user creation/update
        test_data = {
            "username": "testuser",
            "email": "test@example.com",
            "role": "admin",  # Try to assign admin role
            "is_admin": True,
            "permissions": ["read", "write", "delete"]
        }
        
        try:
            response = requests.post(urljoin(base_url, "/api/users"), 
                                   json=test_data, headers=headers, timeout=10)
            results["tests"].append({
                "endpoint": "/api/users",
                "status_code": response.status_code,
                "vulnerable": response.status_code == 200
            })
        except Exception as e:
            results["tests"].append({
                "endpoint": "/api/users",
                "error": str(e)
            })
        
        return results
    
    def test_security_misconfiguration(self, base_url: str, headers: Dict = None) -> Dict:
        """Test for security misconfiguration"""
        results = {"vulnerability": "Security Misconfiguration", "tests": []}
        
        # Test for common misconfigurations
        misconfig_tests = [
            "/.env",
            "/config.json",
            "/api/docs",
            "/swagger.json",
            "/api/v1/users",
            "/debug"
        ]
        
        for endpoint in misconfig_tests:
            try:
                response = requests.get(urljoin(base_url, endpoint), headers=headers, timeout=10)
                results["tests"].append({
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "vulnerable": response.status_code == 200
                })
            except Exception as e:
                results["tests"].append({
                    "endpoint": endpoint,
                    "error": str(e)
                })
        
        return results
    
    def test_injection(self, base_url: str, headers: Dict = None) -> Dict:
        """Test for injection vulnerabilities"""
        results = {"vulnerability": "Injection", "tests": []}
        
        # SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --"
        ]
        
        for payload in sql_payloads:
            try:
                response = requests.get(urljoin(base_url, f"/api/search?q={payload}"), 
                                      headers=headers, timeout=10)
                results["tests"].append({
                    "payload": payload,
                    "status_code": response.status_code,
                    "vulnerable": "error" in response.text.lower() or "sql" in response.text.lower()
                })
            except Exception as e:
                results["tests"].append({
                    "payload": payload,
                    "error": str(e)
                })
        
        return results
    
    def test_improper_assets_management(self, base_url: str, headers: Dict = None) -> Dict:
        """Test for improper assets management"""
        results = {"vulnerability": "Improper Assets Management", "tests": []}
        
        # Test for exposed API versions
        version_endpoints = [
            "/api/v1",
            "/api/v2", 
            "/api/v3",
            "/api/legacy"
        ]
        
        for endpoint in version_endpoints:
            try:
                response = requests.get(urljoin(base_url, endpoint), headers=headers, timeout=10)
                results["tests"].append({
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "accessible": response.status_code == 200
                })
            except Exception as e:
                results["tests"].append({
                    "endpoint": endpoint,
                    "error": str(e)
                })
        
        return results
    
    def test_insufficient_logging(self, base_url: str, headers: Dict = None) -> Dict:
        """Test for insufficient logging and monitoring"""
        results = {"vulnerability": "Insufficient Logging", "tests": []}
        
        # Test various attack patterns
        attack_patterns = [
            "/api/admin/delete",
            "/api/users/1/delete",
            "/api/config/update"
        ]
        
        for endpoint in attack_patterns:
            try:
                response = requests.delete(urljoin(base_url, endpoint), headers=headers, timeout=10)
                results["tests"].append({
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "logged": "log" in response.headers.get('server', '').lower()
                })
            except Exception as e:
                results["tests"].append({
                    "endpoint": endpoint,
                    "error": str(e)
                })
        
        return results
    
    def run_full_test(self, base_url: str, headers: Dict = None) -> Dict:
        """Run all API security tests"""
        results = {
            "target": base_url,
            "timestamp": time.time(),
            "tests": []
        }
        
        for test_name, test_func in self.test_cases.items():
            try:
                test_result = test_func(base_url, headers)
                results["tests"].append(test_result)
            except Exception as e:
                results["tests"].append({
                    "vulnerability": test_name,
                    "error": str(e)
                })
        
        return results

# Plugin instance
plugin = AdvancedAPITester()
