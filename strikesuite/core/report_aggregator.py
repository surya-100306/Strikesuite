#!/usr/bin/env python3
"""
Report Data Aggregator
Connects all assessment results to comprehensive reporting
"""

import json
import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

from .assessment_results import (
    AssessmentResultsManager, AssessmentType, SeverityLevel,
    NetworkHost, Vulnerability, APITestResult, BruteForceResult, ExploitResult
)

class ReportDataAggregator:
    """Aggregates all assessment results for comprehensive reporting"""
    
    def __init__(self, results_manager: AssessmentResultsManager = None):
        self.results_manager = results_manager or AssessmentResultsManager()
        self.report_data = {}
    
    def aggregate_all_results(self) -> Dict[str, Any]:
        """Aggregate all assessment results into comprehensive report data"""
        if not self.results_manager.current_session:
            return {"error": "No active assessment session"}
        
        # Get all types of results
        network_results = self.results_manager.get_network_scan_results()
        vulnerability_results = self.results_manager.get_vulnerability_results()
        api_results = self.results_manager.get_api_test_results()
        brute_force_results = self.results_manager.get_brute_force_results()
        exploit_results = self.results_manager.get_exploit_results()
        
        # Generate comprehensive report data
        self.report_data = {
            "report_metadata": self._generate_report_metadata(),
            "executive_summary": self._generate_executive_summary(),
            "network_discovery": self._aggregate_network_results(network_results),
            "vulnerability_assessment": self._aggregate_vulnerability_results(vulnerability_results),
            "api_security_testing": self._aggregate_api_results(api_results),
            "brute_force_testing": self._aggregate_brute_force_results(brute_force_results),
            "exploitation_results": self._aggregate_exploit_results(exploit_results),
            "risk_assessment": self._generate_risk_assessment(),
            "recommendations": self._generate_recommendations(),
            "technical_details": self._generate_technical_details(),
            "appendix": self._generate_appendix()
        }
        
        return self.report_data
    
    def _generate_report_metadata(self) -> Dict[str, Any]:
        """Generate report metadata"""
        session = self.results_manager.current_session
        
        return {
            "report_title": f"Security Assessment Report - {session.project_name}",
            "report_date": datetime.datetime.now().strftime("%Y-%m-%d"),
            "assessment_period": {
                "start": session.start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "end": session.end_time.strftime("%Y-%m-%d %H:%M:%S") if session.end_time else "Ongoing"
            },
            "target_scope": session.target_scope,
            "session_id": session.session_id,
            "report_version": "1.0",
            "generated_by": "StrikeSuite Security Testing Framework"
        }
    
    def _generate_executive_summary(self) -> Dict[str, Any]:
        """Generate executive summary"""
        session_summary = self.results_manager.generate_session_summary()
        findings = session_summary.get("findings_summary", {})
        risk_assessment = session_summary.get("risk_assessment", {})
        
        # Calculate key metrics
        total_vulnerabilities = findings.get("vulnerabilities", {}).get("total", 0)
        critical_vulns = findings.get("vulnerabilities", {}).get("by_severity", {}).get("critical", 0)
        high_vulns = findings.get("vulnerabilities", {}).get("by_severity", {}).get("high", 0)
        
        hosts_found = findings.get("network_discovery", {}).get("hosts_found", 0)
        successful_exploits = findings.get("exploitation", {}).get("successful_exploits", 0)
        
        return {
            "overview": f"Security assessment of {len(session_summary.get('target_scope', []))} targets",
            "key_findings": {
                "total_vulnerabilities": total_vulnerabilities,
                "critical_vulnerabilities": critical_vulns,
                "high_vulnerabilities": high_vulns,
                "hosts_discovered": hosts_found,
                "successful_exploits": successful_exploits
            },
            "risk_level": risk_assessment.get("risk_level", "UNKNOWN"),
            "risk_score": risk_assessment.get("risk_score", 0),
            "immediate_actions": self._get_immediate_actions(),
            "overall_assessment": self._get_overall_assessment()
        }
    
    def _get_immediate_actions(self) -> List[str]:
        """Get immediate actions required"""
        actions = []
        findings = self.results_manager.generate_session_summary().get("findings_summary", {})
        
        critical_vulns = findings.get("vulnerabilities", {}).get("by_severity", {}).get("critical", 0)
        if critical_vulns > 0:
            actions.append(f"Address {critical_vulns} critical vulnerabilities immediately")
        
        successful_exploits = findings.get("exploitation", {}).get("successful_exploits", 0)
        if successful_exploits > 0:
            actions.append(f"Review {successful_exploits} successfully exploited systems")
        
        return actions
    
    def _get_overall_assessment(self) -> str:
        """Get overall assessment statement"""
        findings = self.results_manager.generate_session_summary().get("findings_summary", {})
        risk_level = self.results_manager.generate_session_summary().get("risk_assessment", {}).get("risk_level", "UNKNOWN")
        
        total_vulns = findings.get("vulnerabilities", {}).get("total", 0)
        
        if risk_level == "CRITICAL":
            return f"The target environment presents CRITICAL security risks with {total_vulns} vulnerabilities identified. Immediate remediation is required."
        elif risk_level == "HIGH":
            return f"The target environment presents HIGH security risks with {total_vulns} vulnerabilities identified. Prompt remediation is recommended."
        elif risk_level == "MEDIUM":
            return f"The target environment presents MEDIUM security risks with {total_vulns} vulnerabilities identified. Remediation should be planned and implemented."
        elif risk_level == "LOW":
            return f"The target environment presents LOW security risks with {total_vulns} vulnerabilities identified. Regular monitoring and maintenance is recommended."
        else:
            return f"The target environment appears to have minimal security risks with {total_vulns} vulnerabilities identified."
    
    def _aggregate_network_results(self, network_results: List[NetworkHost]) -> Dict[str, Any]:
        """Aggregate network scan results"""
        if not network_results:
            return {"summary": "No network scan results available"}
        
        # Group by status
        up_hosts = [host for host in network_results if host.status == "up"]
        down_hosts = [host for host in network_results if host.status == "down"]
        
        # Collect all open ports
        all_ports = []
        for host in up_hosts:
            all_ports.extend(host.open_ports)
        
        # Group ports by service
        services = {}
        for port_info in all_ports:
            service = port_info.get("service", "unknown")
            if service not in services:
                services[service] = []
            services[service].append(port_info)
        
        return {
            "summary": {
                "total_hosts": len(network_results),
                "up_hosts": len(up_hosts),
                "down_hosts": len(down_hosts),
                "total_open_ports": len(all_ports),
                "unique_services": len(services)
            },
            "hosts": [
                {
                    "ip_address": host.ip_address,
                    "hostname": host.hostname,
                    "status": host.status,
                    "open_ports": len(host.open_ports),
                    "os_info": host.os_info
                }
                for host in network_results
            ],
            "services_discovered": {
                service: len(ports) for service, ports in services.items()
            },
            "detailed_ports": all_ports
        }
    
    def _aggregate_vulnerability_results(self, vulnerability_results: List[Vulnerability]) -> Dict[str, Any]:
        """Aggregate vulnerability scan results"""
        if not vulnerability_results:
            return {"summary": "No vulnerabilities found"}
        
        # Group by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for vuln in vulnerability_results:
            severity = vuln.severity.value if isinstance(vuln.severity, SeverityLevel) else vuln.severity
            severity_counts[severity] += 1
        
        # Get top vulnerabilities by CVSS score
        scored_vulns = [v for v in vulnerability_results if v.cvss_score is not None]
        top_vulns = sorted(scored_vulns, key=lambda x: x.cvss_score or 0, reverse=True)[:10]
        
        return {
            "summary": {
                "total_vulnerabilities": len(vulnerability_results),
                "by_severity": severity_counts,
                "with_cvss_scores": len(scored_vulns)
            },
            "top_vulnerabilities": [
                {
                    "cve_id": vuln.cve_id,
                    "title": vuln.title,
                    "severity": vuln.severity.value if isinstance(vuln.severity, SeverityLevel) else vuln.severity,
                    "cvss_score": vuln.cvss_score,
                    "affected_systems": len(vuln.affected_systems)
                }
                for vuln in top_vulns
            ],
            "all_vulnerabilities": [
                {
                    "cve_id": vuln.cve_id,
                    "title": vuln.title,
                    "description": vuln.description,
                    "severity": vuln.severity.value if isinstance(vuln.severity, SeverityLevel) else vuln.severity,
                    "cvss_score": vuln.cvss_score,
                    "affected_systems": vuln.affected_systems,
                    "remediation": vuln.remediation
                }
                for vuln in vulnerability_results
            ]
        }
    
    def _aggregate_api_results(self, api_results: List[APITestResult]) -> Dict[str, Any]:
        """Aggregate API security test results"""
        if not api_results:
            return {"summary": "No API tests performed"}
        
        # Group by status code
        status_codes = {}
        for result in api_results:
            status = result.status_code
            if status not in status_codes:
                status_codes[status] = 0
            status_codes[status] += 1
        
        # Collect security issues
        all_security_issues = []
        for result in api_results:
            all_security_issues.extend(result.security_issues)
        
        # Group by vulnerability type
        vuln_types = {}
        for issue in all_security_issues:
            if issue not in vuln_types:
                vuln_types[issue] = 0
            vuln_types[issue] += 1
        
        return {
            "summary": {
                "total_endpoints_tested": len(api_results),
                "total_security_issues": len(all_security_issues),
                "unique_vulnerability_types": len(vuln_types)
            },
            "response_codes": status_codes,
            "security_issues_by_type": vuln_types,
            "detailed_results": [
                {
                    "endpoint": result.endpoint,
                    "method": result.method,
                    "status_code": result.status_code,
                    "response_time": result.response_time,
                    "security_issues": result.security_issues,
                    "vulnerability_type": result.vulnerability_type
                }
                for result in api_results
            ]
        }
    
    def _aggregate_brute_force_results(self, brute_force_results: List[BruteForceResult]) -> Dict[str, Any]:
        """Aggregate brute force test results"""
        if not brute_force_results:
            return {"summary": "No brute force tests performed"}
        
        successful_attacks = [r for r in brute_force_results if r.success]
        failed_attacks = [r for r in brute_force_results if not r.success]
        
        # Group by service
        services = {}
        for result in brute_force_results:
            service = result.service
            if service not in services:
                services[service] = {"total": 0, "successful": 0}
            services[service]["total"] += 1
            if result.success:
                services[service]["successful"] += 1
        
        return {
            "summary": {
                "total_attempts": len(brute_force_results),
                "successful_attacks": len(successful_attacks),
                "failed_attacks": len(failed_attacks),
                "success_rate": len(successful_attacks) / len(brute_force_results) * 100 if brute_force_results else 0
            },
            "by_service": services,
            "successful_credentials": [
                {
                    "target": result.target,
                    "service": result.service,
                    "username": result.username,
                    "attempts": result.attempts,
                    "time_taken": result.time_taken
                }
                for result in successful_attacks
            ],
            "detailed_results": [
                {
                    "target": result.target,
                    "service": result.service,
                    "success": result.success,
                    "attempts": result.attempts,
                    "time_taken": result.time_taken,
                    "error_message": result.error_message
                }
                for result in brute_force_results
            ]
        }
    
    def _aggregate_exploit_results(self, exploit_results: List[ExploitResult]) -> Dict[str, Any]:
        """Aggregate exploitation results"""
        if not exploit_results:
            return {"summary": "No exploitation attempts made"}
        
        successful_exploits = [r for r in exploit_results if r.success]
        failed_exploits = [r for r in exploit_results if not r.success]
        
        # Group by exploit
        exploits = {}
        for result in exploit_results:
            exploit = result.exploit_name
            if exploit not in exploits:
                exploits[exploit] = {"total": 0, "successful": 0}
            exploits[exploit]["total"] += 1
            if result.success:
                exploits[exploit]["successful"] += 1
        
        return {
            "summary": {
                "total_exploits_attempted": len(exploit_results),
                "successful_exploits": len(successful_exploits),
                "failed_exploits": len(failed_exploits),
                "success_rate": len(successful_exploits) / len(exploit_results) * 100 if exploit_results else 0
            },
            "by_exploit": exploits,
            "successful_exploits": [
                {
                    "target": result.target,
                    "exploit_name": result.exploit_name,
                    "payload": result.payload,
                    "privilege_escalation": result.privilege_escalation,
                    "output": result.output
                }
                for result in successful_exploits
            ],
            "detailed_results": [
                {
                    "target": result.target,
                    "exploit_name": result.exploit_name,
                    "success": result.success,
                    "payload": result.payload,
                    "error_message": result.error_message
                }
                for result in exploit_results
            ]
        }
    
    def _generate_risk_assessment(self) -> Dict[str, Any]:
        """Generate comprehensive risk assessment"""
        session_summary = self.results_manager.generate_session_summary()
        risk_data = session_summary.get("risk_assessment", {})
        
        return {
            "overall_risk_level": risk_data.get("risk_level", "UNKNOWN"),
            "risk_score": risk_data.get("risk_score", 0),
            "risk_factors": self._identify_risk_factors(),
            "business_impact": self._assess_business_impact(),
            "likelihood_assessment": self._assess_likelihood(),
            "risk_matrix": self._generate_risk_matrix()
        }
    
    def _identify_risk_factors(self) -> List[str]:
        """Identify key risk factors"""
        factors = []
        findings = self.results_manager.generate_session_summary().get("findings_summary", {})
        
        critical_vulns = findings.get("vulnerabilities", {}).get("by_severity", {}).get("critical", 0)
        if critical_vulns > 0:
            factors.append(f"{critical_vulns} critical vulnerabilities present")
        
        successful_exploits = findings.get("exploitation", {}).get("successful_exploits", 0)
        if successful_exploits > 0:
            factors.append(f"{successful_exploits} successful system compromises")
        
        successful_brute_force = findings.get("brute_force", {}).get("successful_attacks", 0)
        if successful_brute_force > 0:
            factors.append(f"{successful_brute_force} successful brute force attacks")
        
        return factors
    
    def _assess_business_impact(self) -> str:
        """Assess potential business impact"""
        findings = self.results_manager.generate_session_summary().get("findings_summary", {})
        critical_vulns = findings.get("vulnerabilities", {}).get("by_severity", {}).get("critical", 0)
        successful_exploits = findings.get("exploitation", {}).get("successful_exploits", 0)
        
        if critical_vulns > 0 or successful_exploits > 0:
            return "HIGH - Critical vulnerabilities and successful exploits indicate significant business risk"
        elif findings.get("vulnerabilities", {}).get("by_severity", {}).get("high", 0) > 5:
            return "MEDIUM-HIGH - Multiple high-severity vulnerabilities present"
        else:
            return "LOW-MEDIUM - Limited security risks identified"
    
    def _assess_likelihood(self) -> str:
        """Assess likelihood of exploitation"""
        findings = self.results_manager.generate_session_summary().get("findings_summary", {})
        successful_exploits = findings.get("exploitation", {}).get("successful_exploits", 0)
        
        if successful_exploits > 0:
            return "HIGH - Successful exploits demonstrate exploitability"
        elif findings.get("vulnerabilities", {}).get("by_severity", {}).get("critical", 0) > 0:
            return "MEDIUM-HIGH - Critical vulnerabilities increase likelihood"
        else:
            return "LOW-MEDIUM - Limited exploitability demonstrated"
    
    def _generate_risk_matrix(self) -> Dict[str, Any]:
        """Generate risk matrix"""
        return {
            "critical": "Immediate action required",
            "high": "Action required within 30 days",
            "medium": "Action required within 90 days",
            "low": "Monitor and plan remediation",
            "info": "Document for awareness"
        }
    
    def _generate_recommendations(self) -> Dict[str, Any]:
        """Generate comprehensive recommendations"""
        session_summary = self.results_manager.generate_session_summary()
        risk_assessment = session_summary.get("risk_assessment", {})
        
        return {
            "immediate_actions": risk_assessment.get("recommendations", []),
            "short_term_recommendations": self._get_short_term_recommendations(),
            "long_term_recommendations": self._get_long_term_recommendations(),
            "security_controls": self._recommend_security_controls(),
            "monitoring_recommendations": self._recommend_monitoring()
        }
    
    def _get_short_term_recommendations(self) -> List[str]:
        """Get short-term recommendations (30-90 days)"""
        recommendations = []
        findings = self.results_manager.generate_session_summary().get("findings_summary", {})
        
        high_vulns = findings.get("vulnerabilities", {}).get("by_severity", {}).get("high", 0)
        if high_vulns > 0:
            recommendations.append(f"Patch {high_vulns} high-severity vulnerabilities")
        
        successful_brute_force = findings.get("brute_force", {}).get("successful_attacks", 0)
        if successful_brute_force > 0:
            recommendations.append("Implement stronger authentication mechanisms")
        
        return recommendations
    
    def _get_long_term_recommendations(self) -> List[str]:
        """Get long-term recommendations (3-12 months)"""
        return [
            "Implement comprehensive security monitoring",
            "Establish regular security assessments",
            "Develop incident response procedures",
            "Create security awareness training program",
            "Implement defense-in-depth strategy"
        ]
    
    def _recommend_security_controls(self) -> List[str]:
        """Recommend security controls"""
        return [
            "Network segmentation",
            "Intrusion detection/prevention systems",
            "Endpoint protection",
            "Security information and event management (SIEM)",
            "Regular security assessments"
        ]
    
    def _recommend_monitoring(self) -> List[str]:
        """Recommend monitoring activities"""
        return [
            "Continuous vulnerability scanning",
            "Network traffic monitoring",
            "Log analysis and correlation",
            "Threat intelligence integration",
            "Regular security reviews"
        ]
    
    def _generate_technical_details(self) -> Dict[str, Any]:
        """Generate technical details section"""
        return {
            "assessment_methodology": self._get_assessment_methodology(),
            "tools_used": self._get_tools_used(),
            "scan_configurations": self._get_scan_configurations(),
            "data_collection": self._get_data_collection_info()
        }
    
    def _get_assessment_methodology(self) -> List[str]:
        """Get assessment methodology"""
        return [
            "Automated vulnerability scanning",
            "Manual penetration testing",
            "Network discovery and enumeration",
            "API security testing",
            "Authentication testing",
            "Exploitation verification"
        ]
    
    def _get_tools_used(self) -> List[str]:
        """Get tools used in assessment"""
        return [
            "StrikeSuite Security Testing Framework",
            "Nmap network scanner",
            "Custom API testing tools",
            "Vulnerability databases (CVE, NVD)",
            "Exploitation frameworks"
        ]
    
    def _get_scan_configurations(self) -> Dict[str, Any]:
        """Get scan configurations"""
        return {
            "network_scan": {
                "port_range": "1-65535",
                "scan_type": "TCP SYN scan",
                "timing": "Aggressive"
            },
            "vulnerability_scan": {
                "plugins": "All enabled",
                "intensity": "High",
                "timeout": "30 seconds"
            }
        }
    
    def _get_data_collection_info(self) -> Dict[str, Any]:
        """Get data collection information"""
        return {
            "collection_period": "Assessment duration",
            "data_types": [
                "Network topology",
                "Service enumeration",
                "Vulnerability data",
                "Exploitation results",
                "Configuration details"
            ],
            "data_retention": "30 days",
            "data_protection": "Encrypted storage"
        }
    
    def _generate_appendix(self) -> Dict[str, Any]:
        """Generate appendix section"""
        return {
            "glossary": self._get_glossary(),
            "references": self._get_references(),
            "contact_information": self._get_contact_info(),
            "disclaimer": self._get_disclaimer()
        }
    
    def _get_glossary(self) -> Dict[str, str]:
        """Get technical glossary"""
        return {
            "CVE": "Common Vulnerabilities and Exposures",
            "CVSS": "Common Vulnerability Scoring System",
            "CWE": "Common Weakness Enumeration",
            "OWASP": "Open Web Application Security Project",
            "API": "Application Programming Interface",
            "DoS": "Denial of Service",
            "SQLi": "SQL Injection",
            "XSS": "Cross-Site Scripting"
        }
    
    def _get_references(self) -> List[str]:
        """Get reference materials"""
        return [
            "OWASP Top 10 - 2021",
            "NIST Cybersecurity Framework",
            "ISO 27001 Security Management",
            "CVE Database (https://cve.mitre.org/)",
            "NVD Database (https://nvd.nist.gov/)"
        ]
    
    def _get_contact_info(self) -> Dict[str, str]:
        """Get contact information"""
        return {
            "assessment_team": "StrikeSuite Security Team",
            "email": "security@strikesuite.com",
            "phone": "+1-555-SECURITY",
            "website": "https://strikesuite.com"
        }
    
    def _get_disclaimer(self) -> str:
        """Get legal disclaimer"""
        return """
        This security assessment report is provided for authorized use only. 
        The information contained herein is confidential and proprietary. 
        Unauthorized distribution or disclosure is prohibited. 
        The assessment was conducted in accordance with applicable laws and regulations.
        """

# Global aggregator instance
report_aggregator = ReportDataAggregator()

__all__ = ['ReportDataAggregator', 'report_aggregator']

