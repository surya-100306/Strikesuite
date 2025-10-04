#!/usr/bin/env python3
"""
Subdomain Enumeration Plugin
Advanced subdomain discovery and enumeration
"""

import requests
import dns.resolver
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Set

class SubdomainEnumeration:
    """Subdomain enumeration plugin"""
    
    def __init__(self):
        self.name = "Subdomain Enumeration"
        self.version = "1.0.0"
        self.description = "Advanced subdomain discovery and enumeration"
        self.author = "StrikeSuite Team"
        
        # Common subdomains to test
        self.common_subdomains = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "ns3", "m", "imap", "test",
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns4",
            "mail2", "new", "mysql", "old", "www1", "beta", "api", "stage", "staging",
            "app", "dev2", "m2", "my", "secure", "shop", "sql", "support", "web", "media"
        ]
        
        # DNS servers to use
        self.dns_servers = [
            "8.8.8.8",
            "8.8.4.4", 
            "1.1.1.1",
            "1.0.0.1"
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
        return self.enumerate_subdomains(target, options)
    
    def validate_target(self, target):
        """Validate target"""
        return '.' in target and not target.startswith(('http://', 'https://'))
    
    def get_requirements(self):
        """Return required dependencies"""
        return ['requests', 'dnspython', 'socket']
    
    def dns_enumeration(self, domain: str) -> List[str]:
        """DNS-based subdomain enumeration"""
        found_subdomains = []
        
        for subdomain in self.common_subdomains:
            try:
                full_domain = f"{subdomain}.{domain}"
                answers = dns.resolver.resolve(full_domain, 'A')
                if answers:
                    found_subdomains.append(full_domain)
            except:
                pass
        
        return found_subdomains
    
    def certificate_transparency(self, domain: str) -> List[str]:
        """Certificate Transparency log enumeration"""
        found_subdomains = []
        
        try:
            # Use crt.sh API
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for cert in data:
                    name_value = cert.get('name_value', '')
                    if domain in name_value:
                        found_subdomains.append(name_value)
        except:
            pass
        
        return found_subdomains
    
    def brute_force_enumeration(self, domain: str, wordlist: List[str] = None) -> List[str]:
        """Brute force subdomain enumeration"""
        if wordlist is None:
            wordlist = self.common_subdomains
        
        found_subdomains = []
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{domain}"
                socket.gethostbyname(full_domain)
                found_subdomains.append(full_domain)
            except:
                pass
        
        # Use threading for faster enumeration
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(check_subdomain, wordlist)
        
        return found_subdomains
    
    def passive_enumeration(self, domain: str) -> List[str]:
        """Passive subdomain enumeration using various sources"""
        found_subdomains = []
        
        # Shodan search
        try:
            # This would require Shodan API key
            pass
        except:
            pass
        
        # VirusTotal search
        try:
            # This would require VirusTotal API key
            pass
        except:
            pass
        
        return found_subdomains
    
    def enumerate_subdomains(self, domain: str, methods: List[str] = None) -> Dict:
        """Main enumeration method"""
        if methods is None:
            methods = ["dns", "certificate", "brute_force"]
        
        results = {
            "domain": domain,
            "subdomains": [],
            "methods_used": methods,
            "total_found": 0
        }
        
        all_subdomains = set()
        
        if "dns" in methods:
            dns_results = self.dns_enumeration(domain)
            all_subdomains.update(dns_results)
        
        if "certificate" in methods:
            cert_results = self.certificate_transparency(domain)
            all_subdomains.update(cert_results)
        
        if "brute_force" in methods:
            brute_results = self.brute_force_enumeration(domain)
            all_subdomains.update(brute_results)
        
        results["subdomains"] = list(all_subdomains)
        results["total_found"] = len(all_subdomains)
        
        return results

# Plugin instance
plugin = SubdomainEnumeration()
