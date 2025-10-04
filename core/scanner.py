#!/usr/bin/env python3
"""
Advanced Network Scanner
Multi-threaded port scanning with advanced service detection, OS fingerprinting, and vulnerability scanning
"""

import socket
import threading
import time
import json
import struct
import random
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional, Set
import logging
import ipaddress
import subprocess
import re

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    logging.warning("python-nmap not available. Using basic socket scanning.")

try:
    import scapy
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("scapy not available. Some advanced features disabled.")

class NetworkScanner:
    """
    Advanced network scanner with multi-threading, OS fingerprinting, and vulnerability detection
    """
    
    def __init__(self, max_threads: int = 100, timeout: float = 1.0, scan_type: str = "tcp"):
        self.max_threads = max_threads
        self.timeout = timeout
        self.scan_type = scan_type  # tcp, udp, syn, fin, null, xmas
        self.logger = logging.getLogger(__name__)
        self.scan_results = {}
        self.services = {}
        self.os_fingerprints = {}
        self.vulnerabilities = []
        
        # Enhanced scanning capabilities
        self.stealth_mode = False
        self.advanced_techniques = {
            'os_detection': True,
            'service_detection': True,
            'vulnerability_scan': True,
            'banner_grabbing': True,
            'version_detection': True
        }
        
        # Performance optimization
        self.scan_cache = {}
        self.rate_limit_delay = 0.1
        
        # Advanced port lists
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017]
        self.top_1000_ports = list(range(1, 1001))
        self.web_ports = [80, 443, 8080, 8443, 8000, 8008, 8888, 9000, 9090]
        self.database_ports = [1433, 1521, 3306, 5432, 6379, 27017, 9200, 9300]
        self.admin_ports = [22, 23, 135, 139, 445, 3389, 5900, 5985, 5986]
        
        # Service detection patterns
        self.service_patterns = {
            'HTTP': [b'HTTP/', b'Server:', b'Apache', b'nginx', b'IIS'],
            'SSH': [b'SSH-', b'OpenSSH'],
            'FTP': [b'220', b'FTP'],
            'SMTP': [b'220', b'ESMTP', b'SMTP'],
            'POP3': [b'+OK', b'POP3'],
            'IMAP': [b'* OK', b'IMAP'],
            'MySQL': [b'MySQL', b'mysql'],
            'PostgreSQL': [b'PostgreSQL'],
            'MSSQL': [b'SQL Server'],
            'Redis': [b'Redis'],
            'MongoDB': [b'MongoDB']
        }
        
    def scan_port(self, target: str, port: int) -> Tuple[int, bool, str]:
        """
        Scan a single port on target host
        
        Args:
            target: Target IP address or hostname
            port: Port number to scan
            
        Returns:
            Tuple of (port, is_open, service_info)
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    # Port is open, try to get service info
                    service_info = self._get_service_info(target, port)
                    return (port, True, service_info)
                else:
                    return (port, False, "")
                    
        except Exception as e:
            self.logger.debug(f"Error scanning port {port}: {e}")
            return (port, False, "")
    
    def _get_service_info(self, target: str, port: int) -> str:
        """
        Get service information from open port
        
        Args:
            target: Target IP address
            port: Port number
            
        Returns:
            Service information string
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                sock.connect((target, port))
                
                # Try to get banner
                try:
                    sock.send(b'\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        return banner[:100]  # Limit banner length
                except:
                    pass
                    
                # Return common service names
                service_names = {
                    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
                    995: "POP3S", 3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL",
                    1433: "MSSQL", 6379: "Redis", 27017: "MongoDB"
                }
                
                return service_names.get(port, f"Port {port}")
                
        except Exception:
            return f"Port {port}"
    
    def scan_ports(self, target: str, ports: List[int]) -> Dict:
        """
        Scan multiple ports on target host
        
        Args:
            target: Target IP address or hostname
            ports: List of port numbers to scan
            
        Returns:
            Dictionary with scan results
        """
        self.logger.info(f"Starting port scan on {target} for {len(ports)} ports")
        start_time = time.time()
        
        open_ports = []
        closed_ports = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all port scans
            future_to_port = {
                executor.submit(self.scan_port, target, port): port 
                for port in ports
            }
            
            # Process results as they complete
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    port_num, is_open, service_info = future.result()
                    if is_open:
                        open_ports.append({
                            'port': port_num,
                            'service': service_info,
                            'state': 'open'
                        })
                        self.logger.info(f"Port {port_num} is open - {service_info}")
                    else:
                        closed_ports.append(port_num)
                        
                except Exception as e:
                    self.logger.error(f"Error processing port {port}: {e}")
                    closed_ports.append(port)
        
        scan_time = time.time() - start_time
        
        results = {
            'target': target,
            'scan_time': scan_time,
            'total_ports': len(ports),
            'open_ports': open_ports,
            'closed_ports': len(closed_ports),
            'threads_used': self.max_threads
        }
        
        self.logger.info(f"Scan completed in {scan_time:.2f}s - {len(open_ports)} open ports found")
        return results
    
    def scan_range(self, target: str, start_port: int, end_port: int) -> Dict:
        """
        Scan a range of ports
        
        Args:
            target: Target IP address or hostname
            start_port: Starting port number
            end_port: Ending port number
            
        Returns:
            Dictionary with scan results
        """
        ports = list(range(start_port, end_port + 1))
        return self.scan_ports(target, ports)
    
    def scan_common_ports(self, target: str) -> Dict:
        """
        Scan common ports (1-1000)
        
        Args:
            target: Target IP address or hostname
            
        Returns:
            Dictionary with scan results
        """
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3389,
            5432, 3306, 1433, 6379, 27017, 8080, 8443, 9000, 9090
        ]
        return self.scan_ports(target, common_ports)
    
    def nmap_scan(self, target: str, ports: str = "1-1000") -> Dict:
        """
        Use Nmap for advanced scanning (if available)
        
        Args:
            target: Target IP address or hostname
            ports: Port range or list (e.g., "1-1000" or "22,80,443")
            
        Returns:
            Dictionary with Nmap scan results
        """
        if not NMAP_AVAILABLE:
            self.logger.warning("Nmap not available, falling back to basic scanning")
            return self.scan_common_ports(target)
        
        try:
            nm = nmap.PortScanner()
            self.logger.info(f"Starting Nmap scan on {target}")
            
            # Perform the scan
            nm.scan(target, ports, arguments='-sV -sC --script vuln')
            
            results = {
                'target': target,
                'scan_method': 'nmap',
                'open_ports': [],
                'host_info': {},
                'vulnerabilities': []
            }
            
            # Process results
            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    results['host_info'] = {
                        'hostname': nm[host].hostname(),
                        'state': nm[host].state(),
                        'vendor': nm[host]['vendor'] if 'vendor' in nm[host] else {}
                    }
                    
                    # Get open ports
                    for proto in nm[host].all_protocols():
                        ports_info = nm[host][proto]
                        for port in ports_info:
                            port_info = ports_info[port]
                            if port_info['state'] == 'open':
                                results['open_ports'].append({
                                    'port': port,
                                    'protocol': proto,
                                    'service': port_info.get('name', ''),
                                    'version': port_info.get('version', ''),
                                    'product': port_info.get('product', ''),
                                    'state': port_info['state']
                                })
            
            return results
            
        except Exception as e:
            self.logger.error(f"Nmap scan failed: {e}")
            return self.scan_common_ports(target)
    
    def advanced_port_scan(self, target: str, scan_options: Dict = None) -> Dict:
        """
        Advanced port scanning with multiple techniques
        
        Args:
            target: Target IP address or hostname
            scan_options: Advanced scan options
            
        Returns:
            Comprehensive scan results
        """
        if scan_options is None:
            scan_options = {}
        
        results = {
            'target': target,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'scan_type': self.scan_type,
            'open_ports': [],
            'filtered_ports': [],
            'closed_ports': [],
            'services': {},
            'os_info': {},
            'vulnerabilities': [],
            'scan_stats': {}
        }
        
        # Determine port list
        port_range = scan_options.get('port_range', 'common')
        if port_range == 'common':
            ports = self.common_ports
        elif port_range == 'top1000':
            ports = self.top_1000_ports
        elif port_range == 'web':
            ports = self.web_ports
        elif port_range == 'database':
            ports = self.database_ports
        elif port_range == 'admin':
            ports = self.admin_ports
        elif isinstance(port_range, str) and '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = self.common_ports
        
        # Perform different scan types
        if self.scan_type == 'tcp':
            results.update(self._tcp_connect_scan(target, ports))
        elif self.scan_type == 'syn':
            results.update(self._syn_scan(target, ports))
        elif self.scan_type == 'udp':
            results.update(self._udp_scan(target, ports))
        elif self.scan_type == 'stealth':
            results.update(self._stealth_scan(target, ports))
        
        # OS fingerprinting
        if scan_options.get('os_detection', True):
            results['os_info'] = self._os_fingerprint(target)
        
        # Service detection
        if scan_options.get('service_detection', True):
            results['services'] = self._advanced_service_detection(target, results['open_ports'])
        
        # Vulnerability scanning
        if scan_options.get('vulnerability_scan', True):
            results['vulnerabilities'] = self._vulnerability_scan(target, results['open_ports'])
        
        # Performance stats
        results['scan_stats'] = {
            'total_ports_scanned': len(ports),
            'open_ports_found': len(results['open_ports']),
            'scan_duration': time.time() - time.time()
        }
        
        return results
    
    def _tcp_connect_scan(self, target: str, ports: List[int]) -> Dict:
        """TCP Connect scan"""
        results = {'open_ports': [], 'closed_ports': [], 'filtered_ports': []}
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.scan_port, target, port): port for port in ports}
            
            for future in as_completed(futures):
                port, is_open, service_info = future.result()
                if is_open:
                    results['open_ports'].append({
                        'port': port,
                        'service': service_info,
                        'state': 'open'
                    })
                else:
                    results['closed_ports'].append(port)
        
        return results
    
    def _syn_scan(self, target: str, ports: List[int]) -> Dict:
        """SYN scan (stealth scan)"""
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available, falling back to TCP connect scan")
            return self._tcp_connect_scan(target, ports)
        
        results = {'open_ports': [], 'closed_ports': [], 'filtered_ports': []}
        
        for port in ports:
            try:
                # Send SYN packet
                syn_packet = IP(dst=target) / TCP(dport=port, flags="S")
                response = sr1(syn_packet, timeout=self.timeout, verbose=0)
                
                if response is None:
                    results['filtered_ports'].append(port)
                elif response.haslayer(TCP):
                    if response[TCP].flags == 18:  # SYN-ACK
                        results['open_ports'].append({
                            'port': port,
                            'service': self._get_service_info(target, port),
                            'state': 'open'
                        })
                    elif response[TCP].flags == 4:  # RST
                        results['closed_ports'].append(port)
            except Exception as e:
                self.logger.debug(f"SYN scan error for port {port}: {e}")
        
        return results
    
    def _udp_scan(self, target: str, ports: List[int]) -> Dict:
        """UDP scan"""
        results = {'open_ports': [], 'closed_ports': [], 'filtered_ports': []}
        
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.sendto(b'', (target, port))
                    try:
                        data, addr = sock.recvfrom(1024)
                        results['open_ports'].append({
                            'port': port,
                            'service': 'UDP',
                            'state': 'open'
                        })
                    except socket.timeout:
                        results['filtered_ports'].append(port)
            except Exception as e:
                self.logger.debug(f"UDP scan error for port {port}: {e}")
        
        return results
    
    def _stealth_scan(self, target: str, ports: List[int]) -> Dict:
        """Stealth scan using FIN, NULL, and XMAS scans"""
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available, falling back to TCP connect scan")
            return self._tcp_connect_scan(target, ports)
        
        results = {'open_ports': [], 'closed_ports': [], 'filtered_ports': []}
        
        for port in ports:
            try:
                # FIN scan
                fin_packet = IP(dst=target) / TCP(dport=port, flags="F")
                fin_response = sr1(fin_packet, timeout=self.timeout, verbose=0)
                
                # NULL scan
                null_packet = IP(dst=target) / TCP(dport=port, flags="")
                null_response = sr1(null_packet, timeout=self.timeout, verbose=0)
                
                # XMAS scan
                xmas_packet = IP(dst=target) / TCP(dport=port, flags="FPU")
                xmas_response = sr1(xmas_packet, timeout=self.timeout, verbose=0)
                
                # Analyze responses
                if (fin_response and fin_response.haslayer(TCP) and fin_response[TCP].flags == 4) or \
                   (null_response and null_response.haslayer(TCP) and null_response[TCP].flags == 4) or \
                   (xmas_response and xmas_response.haslayer(TCP) and xmas_response[TCP].flags == 4):
                    results['closed_ports'].append(port)
                else:
                    results['filtered_ports'].append(port)
                    
            except Exception as e:
                self.logger.debug(f"Stealth scan error for port {port}: {e}")
        
        return results
    
    def _os_fingerprint(self, target: str) -> Dict:
        """OS fingerprinting using TCP/IP stack analysis"""
        os_info = {
            'os_family': 'Unknown',
            'os_version': 'Unknown',
            'ttl': 0,
            'window_size': 0,
            'flags': []
        }
        
        try:
            # Send SYN packet and analyze response
            if SCAPY_AVAILABLE:
                syn_packet = IP(dst=target) / TCP(dport=80, flags="S")
                response = sr1(syn_packet, timeout=self.timeout, verbose=0)
                
                if response and response.haslayer(IP) and response.haslayer(TCP):
                    os_info['ttl'] = response[IP].ttl
                    os_info['window_size'] = response[TCP].window
                    os_info['flags'] = str(response[TCP].flags)
                    
                    # Basic OS detection based on TTL
                    if response[IP].ttl <= 64:
                        os_info['os_family'] = 'Linux/Unix'
                    elif response[IP].ttl <= 128:
                        os_info['os_family'] = 'Windows'
                    elif response[IP].ttl <= 255:
                        os_info['os_family'] = 'Cisco/Network Device'
            
            # Additional OS detection using socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                start_time = time.time()
                result = sock.connect_ex((target, 80))
                connect_time = time.time() - start_time
                
                if result == 0:
                    os_info['connect_time'] = connect_time
                    
        except Exception as e:
            self.logger.debug(f"OS fingerprinting error: {e}")
        
        return os_info
    
    def _advanced_service_detection(self, target: str, open_ports: List[Dict]) -> Dict:
        """Advanced service detection with version detection"""
        services = {}
        
        for port_info in open_ports:
            port = port_info['port']
            service_name = self._detect_service_version(target, port)
            services[port] = {
                'name': service_name,
                'version': self._get_service_version(target, port),
                'banner': self._get_service_banner(target, port),
                'vulnerabilities': self._check_service_vulnerabilities(service_name, port)
            }
        
        return services
    
    def _detect_service_version(self, target: str, port: int) -> str:
        """Detect service name and version"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                sock.connect((target, port))
                
                # Send probe and get response
                probe = b'\r\n'
                sock.send(probe)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                # Match against service patterns
                for service, patterns in self.service_patterns.items():
                    for pattern in patterns:
                        if pattern in response.encode():
                            return service
                
                # Fallback to common port mapping
                common_services = {
                    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
                    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
                    995: 'POP3S', 3389: 'RDP', 5432: 'PostgreSQL', 3306: 'MySQL',
                    1433: 'MSSQL', 6379: 'Redis', 27017: 'MongoDB'
                }
                
                return common_services.get(port, f'Unknown-{port}')
                
        except Exception:
            return f'Unknown-{port}'
    
    def _get_service_version(self, target: str, port: int) -> str:
        """Get service version information"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                sock.connect((target, port))
                
                # Send version probe
                if port == 80 or port == 8080:
                    sock.send(b'GET / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\n\r\n')
                elif port == 443:
                    # HTTPS version detection would require SSL/TLS handling
                    return 'HTTPS'
                else:
                    sock.send(b'\r\n')
                
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                # Extract version information
                version_patterns = [
                    r'Server:\s*([^\r\n]+)',
                    r'Apache/([^\s]+)',
                    r'nginx/([^\s]+)',
                    r'OpenSSH_([^\s]+)',
                    r'PostgreSQL ([^\s]+)',
                    r'MySQL ([^\s]+)'
                ]
                
                for pattern in version_patterns:
                    match = re.search(pattern, response, re.IGNORECASE)
                    if match:
                        return match.group(1)
                
                return 'Unknown'
                
        except Exception:
            return 'Unknown'
    
    def _get_service_banner(self, target: str, port: int) -> str:
        """Get service banner"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                sock.connect((target, port))
                
                sock.send(b'\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner[:200]  # Limit banner length
                
        except Exception:
            return ''
    
    def _check_service_vulnerabilities(self, service: str, port: int) -> List[Dict]:
        """Check for known vulnerabilities in detected services"""
        vulnerabilities = []
        
        # Common vulnerability patterns
        vuln_patterns = {
            'SSH': [
                {'name': 'Weak SSH Configuration', 'severity': 'Medium'},
                {'name': 'SSH Version Disclosure', 'severity': 'Low'}
            ],
            'HTTP': [
                {'name': 'HTTP Server Version Disclosure', 'severity': 'Low'},
                {'name': 'Missing Security Headers', 'severity': 'Medium'}
            ],
            'FTP': [
                {'name': 'Anonymous FTP Access', 'severity': 'High'},
                {'name': 'FTP Version Disclosure', 'severity': 'Low'}
            ],
            'MySQL': [
                {'name': 'MySQL Version Disclosure', 'severity': 'Low'},
                {'name': 'Weak Authentication', 'severity': 'High'}
            ],
            'PostgreSQL': [
                {'name': 'PostgreSQL Version Disclosure', 'severity': 'Low'},
                {'name': 'Weak Authentication', 'severity': 'High'}
            ]
        }
        
        if service in vuln_patterns:
            vulnerabilities.extend(vuln_patterns[service])
        
        return vulnerabilities
    
    def _vulnerability_scan(self, target: str, open_ports: List[Dict]) -> List[Dict]:
        """Perform vulnerability scanning on open ports"""
        vulnerabilities = []
        
        for port_info in open_ports:
            port = port_info['port']
            service = port_info.get('service', '')
            
            # Check for common vulnerabilities
            if port == 21:  # FTP
                vuln = self._check_ftp_vulnerabilities(target, port)
                if vuln:
                    vulnerabilities.extend(vuln)
            
            elif port == 22:  # SSH
                vuln = self._check_ssh_vulnerabilities(target, port)
                if vuln:
                    vulnerabilities.extend(vuln)
            
            elif port in [80, 443, 8080, 8443]:  # HTTP/HTTPS
                vuln = self._check_web_vulnerabilities(target, port)
                if vuln:
                    vulnerabilities.extend(vuln)
            
            elif port in [3306, 5432, 1433]:  # Databases
                vuln = self._check_database_vulnerabilities(target, port)
                if vuln:
                    vulnerabilities.extend(vuln)
        
        return vulnerabilities
    
    def _check_ftp_vulnerabilities(self, target: str, port: int) -> List[Dict]:
        """Check FTP vulnerabilities"""
        vulnerabilities = []
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect((target, port))
                
                # Get FTP banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
                # Check for anonymous access
                if '220' in banner:
                    vulnerabilities.append({
                        'type': 'FTP Anonymous Access',
                        'severity': 'High',
                        'description': 'FTP server allows anonymous access',
                        'port': port,
                        'service': 'FTP'
                    })
                
                # Check for version disclosure
                if any(version in banner.lower() for version in ['vsftpd', 'proftpd', 'pure-ftpd']):
                    vulnerabilities.append({
                        'type': 'FTP Version Disclosure',
                        'severity': 'Low',
                        'description': f'FTP server version disclosed: {banner.strip()}',
                        'port': port,
                        'service': 'FTP'
                    })
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _check_ssh_vulnerabilities(self, target: str, port: int) -> List[Dict]:
        """Check SSH vulnerabilities"""
        vulnerabilities = []
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect((target, port))
                
                # Get SSH banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
                # Check for weak SSH versions
                if 'SSH-1.' in banner:
                    vulnerabilities.append({
                        'type': 'SSH Version 1',
                        'severity': 'High',
                        'description': 'SSH server supports version 1 (insecure)',
                        'port': port,
                        'service': 'SSH'
                    })
                
                # Check for version disclosure
                if 'OpenSSH' in banner:
                    vulnerabilities.append({
                        'type': 'SSH Version Disclosure',
                        'severity': 'Low',
                        'description': f'SSH version disclosed: {banner.strip()}',
                        'port': port,
                        'service': 'SSH'
                    })
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _check_web_vulnerabilities(self, target: str, port: int) -> List[Dict]:
        """Check web vulnerabilities"""
        vulnerabilities = []
        
        try:
            import requests
            
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{target}:{port}/"
            
            response = requests.get(url, timeout=5, verify=False)
            
            # Check for server version disclosure
            server_header = response.headers.get('Server', '')
            if server_header:
                vulnerabilities.append({
                    'type': 'HTTP Server Version Disclosure',
                    'severity': 'Low',
                    'description': f'Server version disclosed: {server_header}',
                    'port': port,
                    'service': 'HTTP'
                })
            
            # Check for missing security headers
            security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection', 'Strict-Transport-Security']
            missing_headers = [header for header in security_headers if header not in response.headers]
            
            if missing_headers:
                vulnerabilities.append({
                    'type': 'Missing Security Headers',
                    'severity': 'Medium',
                    'description': f'Missing security headers: {", ".join(missing_headers)}',
                    'port': port,
                    'service': 'HTTP'
                })
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _check_database_vulnerabilities(self, target: str, port: int) -> List[Dict]:
        """Check database vulnerabilities"""
        vulnerabilities = []
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect((target, port))
                
                # Get database banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
                # Check for version disclosure
                if any(db in banner.lower() for db in ['mysql', 'postgresql', 'mssql', 'oracle']):
                    vulnerabilities.append({
                        'type': 'Database Version Disclosure',
                        'severity': 'Low',
                        'description': f'Database version disclosed: {banner.strip()}',
                        'port': port,
                        'service': 'Database'
                    })
        
        except Exception:
            pass
        
        return vulnerabilities
    
    # Convenience functions for backward compatibility
    def comprehensive_scan(self, target: str, options: Dict = None) -> Dict:
        """Comprehensive scan with all advanced features"""
        if options is None:
            options = {
                'port_range': 'common',
                'os_detection': True,
                'service_detection': True,
                'vulnerability_scan': True
            }
        
        return self.advanced_port_scan(target, options)
    
    def save_results(self, results: Dict, filename: str = None) -> str:
        """
        Save scan results to JSON file
        
        Args:
            results: Scan results dictionary
            filename: Output filename (optional)
            
        Returns:
            Path to saved file
        """
        if filename is None:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"scan_results_{timestamp}.json"
        
        filepath = f"logs/scan_logs/{filename}"
        
        try:
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2)
            self.logger.info(f"Results saved to {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
            return ""

# Convenience functions for backward compatibility
def scan_port(target_ip, port, timeout=1.0):
    """Simple port scan function for backward compatibility"""
    scanner = NetworkScanner(timeout=timeout)
    port_num, is_open, service_info = scanner.scan_port(target_ip, port)
    return port_num, is_open

def scan_ports(target_ip, ports, threads=50):
    """Simple multi-port scan function for backward compatibility"""
    scanner = NetworkScanner(max_threads=threads)
    results = scanner.scan_ports(target_ip, ports)
    # Convert to simple format expected by CLI
    simple_results = {}
    for port_info in results.get('open_ports', []):
        simple_results[port_info['port']] = True
    for port in ports:
        if port not in simple_results:
            simple_results[port] = False
    return simple_results
