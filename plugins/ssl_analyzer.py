#!/usr/bin/env python3
"""
SSL/TLS Analyzer Plugin
Comprehensive SSL/TLS security analysis
"""

import ssl
import socket
import requests
from datetime import datetime, timedelta
from typing import Dict, List

class SSLAnalyzer:
    """SSL/TLS security analyzer plugin"""
    
    def __init__(self):
        self.name = "SSL/TLS Analyzer"
        self.version = "1.0.0"
        self.description = "Comprehensive SSL/TLS security analysis"
        self.author = "StrikeSuite Team"
        
        # Weak cipher suites to check for
        self.weak_ciphers = [
            "RC4", "DES", "3DES", "MD5", "SHA1"
        ]
        
        # Strong cipher suites
        self.strong_ciphers = [
            "AES", "ChaCha20", "SHA256", "SHA384", "SHA512"
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
        return self.analyze_ssl(target, options)
    
    def validate_target(self, target):
        """Validate target"""
        return target.startswith(('http://', 'https://'))
    
    def get_requirements(self):
        """Return required dependencies"""
        return ['ssl', 'socket', 'requests']
    
    def get_certificate_info(self, hostname: str, port: int = 443) -> Dict:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    return {
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "version": cert.get('version'),
                        "serial_number": cert.get('serialNumber'),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                        "cipher_suite": cipher[0] if cipher else None,
                        "cipher_version": cipher[1] if cipher else None,
                        "cipher_bits": cipher[2] if cipher else None
                    }
        except Exception as e:
            return {"error": str(e)}
    
    def check_certificate_validity(self, hostname: str, port: int = 443) -> Dict:
        """Check certificate validity and expiration"""
        cert_info = self.get_certificate_info(hostname, port)
        
        if "error" in cert_info:
            return cert_info
        
        results = {
            "valid": True,
            "issues": []
        }
        
        # Check expiration
        if "not_after" in cert_info:
            try:
                expiry_date = datetime.strptime(cert_info["not_after"], "%b %d %H:%M:%S %Y %Z")
                days_until_expiry = (expiry_date - datetime.now()).days
                
                if days_until_expiry < 0:
                    results["valid"] = False
                    results["issues"].append("Certificate expired")
                elif days_until_expiry < 30:
                    results["issues"].append(f"Certificate expires in {days_until_expiry} days")
            except:
                results["issues"].append("Could not parse certificate expiry date")
        
        return results
    
    def check_ssl_configuration(self, hostname: str, port: int = 443) -> Dict:
        """Check SSL/TLS configuration"""
        results = {
            "protocols_supported": [],
            "cipher_suites": [],
            "security_issues": []
        }
        
        # Test different TLS versions
        tls_versions = [
            (ssl.PROTOCOL_TLSv1, "TLS 1.0"),
            (ssl.PROTOCOL_TLSv1_1, "TLS 1.1"), 
            (ssl.PROTOCOL_TLSv1_2, "TLS 1.2"),
            (ssl.PROTOCOL_TLS, "TLS 1.3")
        ]
        
        for version, name in tls_versions:
            try:
                context = ssl.SSLContext(version)
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        results["protocols_supported"].append(name)
            except:
                pass
        
        # Check for weak protocols
        if "TLS 1.0" in results["protocols_supported"]:
            results["security_issues"].append("TLS 1.0 is supported (weak)")
        if "TLS 1.1" in results["protocols_supported"]:
            results["security_issues"].append("TLS 1.1 is supported (weak)")
        
        return results
    
    def check_hsts(self, hostname: str) -> Dict:
        """Check HTTP Strict Transport Security (HSTS)"""
        try:
            response = requests.get(f"https://{hostname}", timeout=10, verify=False)
            hsts_header = response.headers.get('Strict-Transport-Security', '')
            
            return {
                "hsts_enabled": bool(hsts_header),
                "hsts_header": hsts_header,
                "secure": bool(hsts_header)
            }
        except Exception as e:
            return {"error": str(e)}
    
    def comprehensive_analysis(self, hostname: str, port: int = 443) -> Dict:
        """Perform comprehensive SSL/TLS analysis"""
        results = {
            "target": hostname,
            "port": port,
            "certificate": {},
            "configuration": {},
            "hsts": {},
            "overall_score": 0,
            "recommendations": []
        }
        
        # Certificate analysis
        cert_info = self.get_certificate_info(hostname, port)
        results["certificate"] = cert_info
        
        # Certificate validity
        validity = self.check_certificate_validity(hostname, port)
        results["certificate"].update(validity)
        
        # SSL configuration
        config = self.check_ssl_configuration(hostname, port)
        results["configuration"] = config
        
        # HSTS check
        hsts = self.check_hsts(hostname)
        results["hsts"] = hsts
        
        # Calculate overall score
        score = 100
        
        if not results["certificate"].get("valid", True):
            score -= 30
        
        if results["configuration"].get("security_issues"):
            score -= len(results["configuration"]["security_issues"]) * 10
        
        if not results["hsts"].get("secure", False):
            score -= 10
        
        results["overall_score"] = max(0, score)
        
        # Generate recommendations
        if score < 70:
            results["recommendations"].append("SSL/TLS configuration needs improvement")
        if not results["hsts"].get("secure", False):
            results["recommendations"].append("Enable HSTS headers")
        if "TLS 1.0" in results["configuration"].get("protocols_supported", []):
            results["recommendations"].append("Disable TLS 1.0")
        if "TLS 1.1" in results["configuration"].get("protocols_supported", []):
            results["recommendations"].append("Disable TLS 1.1")
        
        return results

# Plugin instance
plugin = SSLAnalyzer()
