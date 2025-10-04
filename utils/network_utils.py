#!/usr/bin/env python3
"""
Network Utilities
Network-related utility functions
"""

import socket
import ipaddress
import re
import logging
from typing import List, Optional, Tuple, Dict
from urllib.parse import urlparse

class NetworkUtils:
    """
    Network utility functions
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def is_valid_ip(self, ip: str) -> bool:
        """
        Check if string is a valid IP address
        
        Args:
            ip: IP address string
            
        Returns:
            True if valid IP, False otherwise
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def is_valid_ip_range(self, ip_range: str) -> bool:
        """
        Check if string is a valid IP range
        
        Args:
            ip_range: IP range string (e.g., "192.168.1.0/24")
            
        Returns:
            True if valid IP range, False otherwise
        """
        try:
            ipaddress.ip_network(ip_range, strict=False)
            return True
        except ValueError:
            return False
    
    def is_valid_hostname(self, hostname: str) -> bool:
        """
        Check if string is a valid hostname
        
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
    
    def is_valid_url(self, url: str) -> bool:
        """
        Check if string is a valid URL
        
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
    
    def resolve_hostname(self, hostname: str) -> Optional[str]:
        """
        Resolve hostname to IP address
        
        Args:
            hostname: Hostname to resolve
            
        Returns:
            IP address or None if failed
        """
        try:
            ip = socket.gethostbyname(hostname)
            return ip
        except socket.gaierror:
            self.logger.warning(f"Failed to resolve hostname: {hostname}")
            return None
    
    def get_hostname(self, ip: str) -> Optional[str]:
        """
        Get hostname for IP address
        
        Args:
            ip: IP address
            
        Returns:
            Hostname or None if failed
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except socket.herror:
            self.logger.warning(f"Failed to get hostname for IP: {ip}")
            return None
    
    def is_port_open(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """
        Check if port is open on host
        
        Args:
            host: Target host
            port: Port number
            timeout: Connection timeout
            
        Returns:
            True if port is open, False otherwise
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                return result == 0
        except Exception:
            return False
    
    def get_service_name(self, port: int, protocol: str = 'tcp') -> str:
        """
        Get service name for port
        
        Args:
            port: Port number
            protocol: Protocol (tcp/udp)
            
        Returns:
            Service name
        """
        # Common port mappings
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL",
            1433: "MSSQL", 6379: "Redis", 27017: "MongoDB", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 9000: "SonarQube", 9090: "Prometheus"
        }
        
        return common_ports.get(port, f"Port-{port}")
    
    def expand_ip_range(self, ip_range: str) -> List[str]:
        """
        Expand IP range to list of IPs
        
        Args:
            ip_range: IP range (e.g., "192.168.1.0/24")
            
        Returns:
            List of IP addresses
        """
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            self.logger.error(f"Invalid IP range: {ip_range}")
            return []
    
    def parse_port_range(self, port_range: str) -> List[int]:
        """
        Parse port range string to list of ports
        
        Args:
            port_range: Port range (e.g., "1-1000" or "22,80,443")
            
        Returns:
            List of port numbers
        """
        ports = []
        
        try:
            if ',' in port_range:
                # Comma-separated ports
                for port in port_range.split(','):
                    port = port.strip()
                    if port.isdigit():
                        ports.append(int(port))
            elif '-' in port_range:
                # Range of ports
                start, end = port_range.split('-', 1)
                start = int(start.strip())
                end = int(end.strip())
                ports = list(range(start, end + 1))
            else:
                # Single port
                if port_range.isdigit():
                    ports.append(int(port_range))
        except ValueError:
            self.logger.error(f"Invalid port range: {port_range}")
        
        return ports
    
    def get_local_ip(self) -> str:
        """
        Get local IP address
        
        Returns:
            Local IP address
        """
        try:
            # Connect to a remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))
                local_ip = sock.getsockname()[0]
                return local_ip
        except Exception:
            return "127.0.0.1"
    
    def get_network_info(self, ip: str) -> Dict:
        """
        Get network information for IP address
        
        Args:
            ip: IP address
            
        Returns:
            Dictionary with network information
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            info = {
                'ip': str(ip_obj),
                'version': ip_obj.version,
                'is_private': ip_obj.is_private,
                'is_loopback': ip_obj.is_loopback,
                'is_multicast': ip_obj.is_multicast,
                'is_reserved': ip_obj.is_reserved
            }
            
            # Get hostname if possible
            hostname = self.get_hostname(ip)
            if hostname:
                info['hostname'] = hostname
            
            return info
            
        except ValueError:
            self.logger.error(f"Invalid IP address: {ip}")
            return {}
    
    def validate_target(self, target: str) -> Dict:
        """
        Validate and analyze target
        
        Args:
            target: Target string (IP, hostname, URL)
            
        Returns:
            Dictionary with target information
        """
        info = {
            'target': target,
            'type': 'unknown',
            'valid': False,
            'resolved_ip': None,
            'hostname': None
        }
        
        try:
            # Check if it's a URL
            if self.is_valid_url(target):
                info['type'] = 'url'
                info['valid'] = True
                parsed = urlparse(target)
                info['hostname'] = parsed.hostname
                if parsed.hostname:
                    resolved_ip = self.resolve_hostname(parsed.hostname)
                    if resolved_ip:
                        info['resolved_ip'] = resolved_ip
            
            # Check if it's an IP address
            elif self.is_valid_ip(target):
                info['type'] = 'ip'
                info['valid'] = True
                info['resolved_ip'] = target
                hostname = self.get_hostname(target)
                if hostname:
                    info['hostname'] = hostname
            
            # Check if it's a hostname
            elif self.is_valid_hostname(target):
                info['type'] = 'hostname'
                info['valid'] = True
                info['hostname'] = target
                resolved_ip = self.resolve_hostname(target)
                if resolved_ip:
                    info['resolved_ip'] = resolved_ip
            
            return info
            
        except Exception as e:
            self.logger.error(f"Error validating target {target}: {e}")
            return info
