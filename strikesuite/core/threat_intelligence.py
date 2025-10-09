#!/usr/bin/env python3
"""
Threat Intelligence Module
Advanced threat intelligence and security analysis capabilities
"""

import json
import requests
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import hashlib
import ipaddress
import re

class ThreatIntelligenceEngine:
    """Advanced threat intelligence engine"""
    
    def __init__(self):
        self.threat_feeds = []
        self.ioc_database = {}
        self.threat_indicators = []
        self.load_threat_feeds()
    
    def load_threat_feeds(self):
        """Load threat intelligence feeds"""
        # Load from local database
        try:
            conn = sqlite3.connect('database/strikesuite.db')
            cursor = conn.cursor()
            
            # Create threat intelligence tables if they don't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    source TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    description TEXT,
                    tags TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_feeds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    feed_name TEXT NOT NULL,
                    feed_url TEXT NOT NULL,
                    feed_type TEXT NOT NULL,
                    last_updated TEXT,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Could not initialize threat intelligence database: {e}")
    
    def analyze_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Analyze IP address reputation"""
        reputation_score = 0
        threats = []
        
        # Check if IP is in threat database
        threat_check = self.check_threat_indicator(ip_address, "ip")
        if threat_check.get("is_threat"):
            reputation_score += 50
            threats.append({
                "type": "Known Threat IP",
                "severity": threat_check["threat_level"],
                "source": threat_check["source"]
            })
        
        # Check for private/reserved IP ranges
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                reputation_score += 10
                threats.append({
                    "type": "Private IP Address",
                    "severity": "Low",
                    "source": "Internal Network"
                })
            elif ip_obj.is_loopback:
                reputation_score += 5
                threats.append({
                    "type": "Loopback Address",
                    "severity": "Info",
                    "source": "Local System"
                })
        except ValueError:
            reputation_score += 20
            threats.append({
                "type": "Invalid IP Address",
                "severity": "Medium",
                "source": "Format Check"
            })
        
        # Determine reputation level
        if reputation_score >= 80:
            reputation_level = "High Risk"
        elif reputation_score >= 50:
            reputation_level = "Medium Risk"
        elif reputation_score >= 20:
            reputation_level = "Low Risk"
        else:
            reputation_level = "Clean"
        
        return {
            "ip_address": ip_address,
            "reputation_score": reputation_score,
            "reputation_level": reputation_level,
            "threats": threats,
            "analysis_timestamp": datetime.now().isoformat()
        }
    
    def analyze_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Analyze domain reputation"""
        reputation_score = 0
        threats = []
        
        # Check if domain is in threat database
        threat_check = self.check_threat_indicator(domain, "domain")
        if threat_check.get("is_threat"):
            reputation_score += 60
            threats.append({
                "type": "Known Malicious Domain",
                "severity": threat_check["threat_level"],
                "source": threat_check["source"]
            })
        
        # Check for suspicious domain patterns
        if self._is_suspicious_domain(domain):
            reputation_score += 40
            threats.append({
                "type": "Suspicious Domain Pattern",
                "severity": "Medium",
                "source": "Pattern Analysis"
            })
        
        # Determine reputation level
        if reputation_score >= 80:
            reputation_level = "High Risk"
        elif reputation_score >= 50:
            reputation_level = "Medium Risk"
        elif reputation_score >= 20:
            reputation_level = "Low Risk"
        else:
            reputation_level = "Clean"
        
        return {
            "domain": domain,
            "reputation_score": reputation_score,
            "reputation_level": reputation_level,
            "threats": threats,
            "analysis_timestamp": datetime.now().isoformat()
        }
    
    def analyze_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """Analyze file hash for malware indicators"""
        reputation_score = 0
        threats = []
        
        # Check if hash is in threat database
        threat_check = self.check_threat_indicator(file_hash, "hash")
        if threat_check.get("is_threat"):
            reputation_score += 80
            threats.append({
                "type": "Known Malware Hash",
                "severity": threat_check["threat_level"],
                "source": threat_check["source"]
            })
        
        # Check hash type and characteristics
        if len(file_hash) == 32:  # MD5
            reputation_score += 10
            threats.append({
                "type": "MD5 Hash (Weak)",
                "severity": "Low",
                "source": "Hash Analysis"
            })
        elif len(file_hash) == 40:  # SHA1
            reputation_score += 5
            threats.append({
                "type": "SHA1 Hash (Deprecated)",
                "severity": "Low",
                "source": "Hash Analysis"
            })
        elif len(file_hash) == 64:  # SHA256
            reputation_score += 0
        else:
            reputation_score += 15
            threats.append({
                "type": "Unknown Hash Format",
                "severity": "Low",
                "source": "Hash Analysis"
            })
        
        # Determine reputation level
        if reputation_score >= 80:
            reputation_level = "High Risk"
        elif reputation_score >= 50:
            reputation_level = "Medium Risk"
        elif reputation_score >= 20:
            reputation_level = "Low Risk"
        else:
            reputation_level = "Clean"
        
        return {
            "file_hash": file_hash,
            "reputation_score": reputation_score,
            "reputation_level": reputation_level,
            "threats": threats,
            "analysis_timestamp": datetime.now().isoformat()
        }
    
    def check_threat_indicator(self, indicator_value: str, indicator_type: str = None) -> Dict[str, Any]:
        """Check if indicator is known threat"""
        try:
            conn = sqlite3.connect('database/strikesuite.db')
            cursor = conn.cursor()
            
            if indicator_type:
                cursor.execute('''
                    SELECT * FROM threat_indicators 
                    WHERE indicator_value = ? AND indicator_type = ?
                ''', (indicator_value, indicator_type))
            else:
                cursor.execute('''
                    SELECT * FROM threat_indicators 
                    WHERE indicator_value = ?
                ''', (indicator_value,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return {
                    "is_threat": True,
                    "threat_level": result[3],
                    "source": result[4],
                    "first_seen": result[5],
                    "last_seen": result[6],
                    "description": result[7],
                    "tags": json.loads(result[8]) if result[8] else []
                }
            else:
                return {"is_threat": False}
                
        except Exception as e:
            print(f"Failed to check threat indicator: {e}")
            return {"is_threat": False, "error": str(e)}
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain has suspicious characteristics"""
        # Check for common malicious domain patterns
        suspicious_patterns = [
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP in domain
            r'[a-z]{1,3}[0-9]{1,3}[a-z]{1,3}',  # Random character/number mix
            r'[0-9]{8,}',  # Long number sequences
            r'[a-z]{15,}',  # Very long random strings
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain):
                return True
        
        return False
    
    def generate_threat_report(self, indicators: List[str]) -> Dict[str, Any]:
        """Generate comprehensive threat intelligence report"""
        report = {
            "analysis_timestamp": datetime.now().isoformat(),
            "total_indicators": len(indicators),
            "threat_analysis": [],
            "summary": {
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
                "clean": 0
            }
        }
        
        for indicator in indicators:
            # Determine indicator type
            if self._is_ip_address(indicator):
                analysis = self.analyze_ip_reputation(indicator)
            elif self._is_domain(indicator):
                analysis = self.analyze_domain_reputation(indicator)
            elif self._is_hash(indicator):
                analysis = self.analyze_file_hash(indicator)
            else:
                analysis = {
                    "indicator": indicator,
                    "reputation_level": "Unknown",
                    "threats": [{"type": "Unknown Indicator Type", "severity": "Info"}]
                }
            
            report["threat_analysis"].append(analysis)
            
            # Update summary
            level = analysis.get("reputation_level", "Unknown")
            if level == "High Risk":
                report["summary"]["high_risk"] += 1
            elif level == "Medium Risk":
                report["summary"]["medium_risk"] += 1
            elif level == "Low Risk":
                report["summary"]["low_risk"] += 1
            else:
                report["summary"]["clean"] += 1
        
        return report
    
    def _is_ip_address(self, indicator: str) -> bool:
        """Check if indicator is an IP address"""
        try:
            ipaddress.ip_address(indicator)
            return True
        except ValueError:
            return False
    
    def _is_domain(self, indicator: str) -> bool:
        """Check if indicator is a domain"""
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, indicator))
    
    def _is_hash(self, indicator: str) -> bool:
        """Check if indicator is a file hash"""
        hash_patterns = [
            r'^[a-fA-F0-9]{32}$',  # MD5
            r'^[a-fA-F0-9]{40}$',  # SHA1
            r'^[a-fA-F0-9]{64}$',  # SHA256
        ]
        
        for pattern in hash_patterns:
            if re.match(pattern, indicator):
                return True
        
        return False

