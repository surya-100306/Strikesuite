#!/usr/bin/env python3
"""
Enhanced Network Scanner
Advanced network scanning with modern features and improved performance
"""

import socket
import threading
import time
import json
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Tuple
import subprocess
import platform
import psutil
from datetime import datetime

class EnhancedNetworkScanner:
    """Enhanced network scanner with advanced features"""
    
    def __init__(self, max_threads=100, timeout=3):
        self.max_threads = max_threads
        self.timeout = timeout
        self.scan_results = []
        self.scan_progress = 0
        self.scan_total = 0
        self.is_scanning = False
        self.scan_start_time = None
        
        # Common ports to scan
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995,
            1723, 3389, 5900, 8080, 8443, 8888, 9000, 9090
        ]
        
        # Service detection mapping
        self.service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
            443: "HTTPS", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
            3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
            8888: "HTTP-Alt", 9000: "HTTP-Alt", 9090: "HTTP-Alt"
        }
    
    def scan_network_range(self, network_range: str, port_list: List[int] = None) -> Dict[str, Any]:
        """
        Scan a network range with enhanced features
        
        Args:
            network_range: Network range to scan (e.g., "192.168.1.0/24")
            port_list: List of ports to scan (default: common ports)
        
        Returns:
            Dictionary containing scan results
        """
        if port_list is None:
            port_list = self.common_ports
        
        self.is_scanning = True
        self.scan_start_time = datetime.now()
        self.scan_results = []
        
        try:
            # Parse network range
            network = ipaddress.ip_network(network_range, strict=False)
            hosts = list(network.hosts())
            self.scan_total = len(hosts) * len(port_list)
            self.scan_progress = 0
            
            print(f"Starting enhanced scan of {network_range}")
            print(f"Scanning {len(hosts)} hosts with {len(port_list)} ports each")
            print(f"Using {self.max_threads} threads")
            
            # Use ThreadPoolExecutor for concurrent scanning
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Submit all scan tasks
                future_to_host_port = {}
                
                for host in hosts:
                    for port in port_list:
                        future = executor.submit(self._scan_host_port, str(host), port)
                        future_to_host_port[future] = (str(host), port)
                
                # Process completed scans
                for future in as_completed(future_to_host_port):
                    host, port = future_to_host_port[future]
                    try:
                        result = future.result()
                        if result:
                            self.scan_results.append(result)
                    except Exception as e:
                        print(f"Error scanning {host}:{port} - {e}")
                    
                    self.scan_progress += 1
                    progress_percent = (self.scan_progress / self.scan_total) * 100
                    print(f"Progress: {progress_percent:.1f}% ({self.scan_progress}/{self.scan_total})")
            
            # Generate comprehensive report
            scan_duration = datetime.now() - self.scan_start_time
            report = self._generate_scan_report(scan_duration)
            
            self.is_scanning = False
            return report
            
        except Exception as e:
            self.is_scanning = False
            print(f"Scan failed: {e}")
            return {"error": str(e)}
    
    def _scan_host_port(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Scan a single host:port combination"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                # Port is open
                service = self.service_map.get(port, "Unknown")
                banner = self._get_banner(host, port)
                
                return {
                    "host": host,
                    "port": port,
                    "status": "open",
                    "service": service,
                    "banner": banner,
                    "timestamp": datetime.now().isoformat()
                }
            
        except Exception as e:
            pass
        
        return None
    
    def _get_banner(self, host: str, port: int) -> str:
        """Get service banner from open port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            
            # Send a simple request for HTTP services
            if port in [80, 8080, 8000, 8888, 9000, 9090]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner[:200]  # Limit banner length
            
        except Exception:
            return ""
    
    def _generate_scan_report(self, duration) -> Dict[str, Any]:
        """Generate comprehensive scan report"""
        # Group results by host
        hosts = {}
        for result in self.scan_results:
            host = result["host"]
            if host not in hosts:
                hosts[host] = {
                    "host": host,
                    "open_ports": [],
                    "services": [],
                    "vulnerabilities": []
                }
            
            hosts[host]["open_ports"].append(result["port"])
            hosts[host]["services"].append({
                "port": result["port"],
                "service": result["service"],
                "banner": result["banner"]
            })
        
        # Calculate statistics
        total_hosts = len(hosts)
        total_ports = len(self.scan_results)
        scan_rate = total_ports / duration.total_seconds() if duration.total_seconds() > 0 else 0
        
        return {
            "scan_info": {
                "network_range": "scanned_range",
                "start_time": self.scan_start_time.isoformat(),
                "duration": str(duration),
                "total_hosts": total_hosts,
                "total_ports": total_ports,
                "scan_rate": f"{scan_rate:.2f} ports/second"
            },
            "hosts": list(hosts.values()),
            "statistics": {
                "hosts_with_open_ports": total_hosts,
                "most_common_ports": self._get_most_common_ports(),
                "service_distribution": self._get_service_distribution()
            }
        }
    
    def _get_most_common_ports(self) -> List[Dict[str, Any]]:
        """Get most common open ports"""
        port_counts = {}
        for result in self.scan_results:
            port = result["port"]
            port_counts[port] = port_counts.get(port, 0) + 1
        
        return [{"port": port, "count": count} for port, count in sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]]
    
    def _get_service_distribution(self) -> Dict[str, int]:
        """Get service distribution"""
        service_counts = {}
        for result in self.scan_results:
            service = result["service"]
            service_counts[service] = service_counts.get(service, 0) + 1
        
        return service_counts
    
    def get_scan_progress(self) -> Dict[str, Any]:
        """Get current scan progress"""
        return {
            "is_scanning": self.is_scanning,
            "progress": self.scan_progress,
            "total": self.scan_total,
            "percentage": (self.scan_progress / self.scan_total * 100) if self.scan_total > 0 else 0,
            "duration": str(datetime.now() - self.scan_start_time) if self.scan_start_time else "0:00:00"
        }
    
    def stop_scan(self):
        """Stop current scan"""
        self.is_scanning = False
        print("Scan stopped by user")

