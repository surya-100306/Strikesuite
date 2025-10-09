#!/usr/bin/env python3
"""
Assessment Results Data Model
Unified data structure for all security assessment results
"""

import json
import datetime
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum

class AssessmentType(Enum):
    """Types of security assessments"""
    NETWORK_SCAN = "network_scan"
    VULNERABILITY_SCAN = "vulnerability_scan"
    API_TEST = "api_test"
    BRUTE_FORCE = "brute_force"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    CVE_ANALYSIS = "cve_analysis"

class SeverityLevel(Enum):
    """Severity levels for findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class NetworkHost:
    """Network host information"""
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    os_info: Optional[str] = None
    status: str = "up"
    response_time: Optional[float] = None
    open_ports: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []

@dataclass
class PortInfo:
    """Port information"""
    port: int
    protocol: str
    service: Optional[str] = None
    version: Optional[str] = None
    state: str = "open"
    banner: Optional[str] = None
    cpe: Optional[str] = None

@dataclass
class Vulnerability:
    """Vulnerability information"""
    cve_id: Optional[str] = None
    title: str = ""
    description: str = ""
    severity: SeverityLevel = SeverityLevel.INFO
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    affected_systems: List[str] = None
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = None
    discovered_date: Optional[datetime.datetime] = None
    
    def __post_init__(self):
        if self.affected_systems is None:
            self.affected_systems = []
        if self.references is None:
            self.references = []
        if self.discovered_date is None:
            self.discovered_date = datetime.datetime.now()

@dataclass
class APITestResult:
    """API security test result"""
    endpoint: str
    method: str
    status_code: int
    response_time: float
    security_issues: List[str] = None
    headers: Dict[str, str] = None
    payload: Optional[str] = None
    vulnerability_type: Optional[str] = None
    
    def __post_init__(self):
        if self.security_issues is None:
            self.security_issues = []
        if self.headers is None:
            self.headers = {}

@dataclass
class BruteForceResult:
    """Brute force attack result"""
    target: str
    service: str
    username: Optional[str] = None
    password: Optional[str] = None
    success: bool = False
    attempts: int = 0
    time_taken: float = 0.0
    error_message: Optional[str] = None

@dataclass
class ExploitResult:
    """Exploitation attempt result"""
    target: str
    exploit_name: str
    success: bool = False
    payload: Optional[str] = None
    output: Optional[str] = None
    error_message: Optional[str] = None
    privilege_escalation: bool = False

@dataclass
class AssessmentResult:
    """Individual assessment result"""
    assessment_id: str
    assessment_type: AssessmentType
    target: str
    start_time: datetime.datetime
    end_time: Optional[datetime.datetime] = None
    status: str = "running"
    results: List[Any] = None
    summary: Dict[str, Any] = None
    errors: List[str] = None
    
    def __post_init__(self):
        if self.results is None:
            self.results = []
        if self.summary is None:
            self.summary = {}
        if self.errors is None:
            self.errors = []

@dataclass
class AssessmentSession:
    """Complete assessment session"""
    session_id: str
    project_name: str
    target_scope: List[str]
    start_time: datetime.datetime
    end_time: Optional[datetime.datetime] = None
    assessments: List[AssessmentResult] = None
    overall_summary: Dict[str, Any] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.assessments is None:
            self.assessments = []
        if self.overall_summary is None:
            self.overall_summary = {}
        if self.metadata is None:
            self.metadata = {}

class AssessmentResultsManager:
    """Manager for assessment results and report integration"""
    
    def __init__(self, db_path: str = "database/strikesuite.db"):
        self.db_path = db_path
        self.current_session: Optional[AssessmentSession] = None
        self.results_cache: Dict[str, Any] = {}
    
    def start_session(self, project_name: str, target_scope: List[str]) -> str:
        """Start a new assessment session"""
        session_id = f"session_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        self.current_session = AssessmentSession(
            session_id=session_id,
            project_name=project_name,
            target_scope=target_scope,
            start_time=datetime.datetime.now()
        )
        
        return session_id
    
    def add_assessment_result(self, assessment_type: AssessmentType, target: str, 
                            results: List[Any], summary: Dict[str, Any] = None) -> str:
        """Add assessment result to current session"""
        if not self.current_session:
            raise ValueError("No active session. Start a session first.")
        
        assessment_id = f"{assessment_type.value}_{datetime.datetime.now().strftime('%H%M%S')}"
        
        assessment = AssessmentResult(
            assessment_id=assessment_id,
            assessment_type=assessment_type,
            target=target,
            start_time=datetime.datetime.now(),
            end_time=datetime.datetime.now(),
            status="completed",
            results=results,
            summary=summary or {}
        )
        
        self.current_session.assessments.append(assessment)
        return assessment_id
    
    def get_network_scan_results(self) -> List[NetworkHost]:
        """Get all network scan results from current session"""
        network_results = []
        
        if self.current_session:
            for assessment in self.current_session.assessments:
                if assessment.assessment_type == AssessmentType.NETWORK_SCAN:
                    network_results.extend(assessment.results)
        
        return network_results
    
    def get_vulnerability_results(self) -> List[Vulnerability]:
        """Get all vulnerability scan results from current session"""
        vulnerabilities = []
        
        if self.current_session:
            for assessment in self.current_session.assessments:
                if assessment.assessment_type == AssessmentType.VULNERABILITY_SCAN:
                    vulnerabilities.extend(assessment.results)
        
        return vulnerabilities
    
    def get_api_test_results(self) -> List[APITestResult]:
        """Get all API test results from current session"""
        api_results = []
        
        if self.current_session:
            for assessment in self.current_session.assessments:
                if assessment.assessment_type == AssessmentType.API_TEST:
                    api_results.extend(assessment.results)
        
        return api_results
    
    def get_brute_force_results(self) -> List[BruteForceResult]:
        """Get all brute force results from current session"""
        brute_force_results = []
        
        if self.current_session:
            for assessment in self.current_session.assessments:
                if assessment.assessment_type == AssessmentType.BRUTE_FORCE:
                    brute_force_results.extend(assessment.results)
        
        return brute_force_results
    
    def get_exploit_results(self) -> List[ExploitResult]:
        """Get all exploitation results from current session"""
        exploit_results = []
        
        if self.current_session:
            for assessment in self.current_session.assessments:
                if assessment.assessment_type == AssessmentType.EXPLOITATION:
                    exploit_results.extend(assessment.results)
        
        return exploit_results
    
    def generate_session_summary(self) -> Dict[str, Any]:
        """Generate comprehensive summary of current session"""
        if not self.current_session:
            return {}
        
        summary = {
            "session_info": {
                "session_id": self.current_session.session_id,
                "project_name": self.current_session.project_name,
                "target_scope": self.current_session.target_scope,
                "start_time": self.current_session.start_time.isoformat(),
                "end_time": self.current_session.end_time.isoformat() if self.current_session.end_time else None,
                "duration": self._calculate_duration()
            },
            "assessment_summary": {
                "total_assessments": len(self.current_session.assessments),
                "completed_assessments": len([a for a in self.current_session.assessments if a.status == "completed"]),
                "failed_assessments": len([a for a in self.current_session.assessments if a.status == "failed"])
            },
            "findings_summary": self._generate_findings_summary(),
            "risk_assessment": self._generate_risk_assessment()
        }
        
        return summary
    
    def _calculate_duration(self) -> Optional[str]:
        """Calculate session duration"""
        if not self.current_session or not self.current_session.end_time:
            return None
        
        duration = self.current_session.end_time - self.current_session.start_time
        return str(duration)
    
    def _generate_findings_summary(self) -> Dict[str, Any]:
        """Generate summary of all findings"""
        vulnerabilities = self.get_vulnerability_results()
        network_hosts = self.get_network_scan_results()
        api_results = self.get_api_test_results()
        brute_force_results = self.get_brute_force_results()
        exploit_results = self.get_exploit_results()
        
        # Count vulnerabilities by severity
        vuln_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.severity.value if isinstance(vuln.severity, SeverityLevel) else vuln.severity
            vuln_counts[severity] += 1
        
        return {
            "vulnerabilities": {
                "total": len(vulnerabilities),
                "by_severity": vuln_counts
            },
            "network_discovery": {
                "hosts_found": len(network_hosts),
                "open_ports": sum(len(host.open_ports) for host in network_hosts)
            },
            "api_security": {
                "endpoints_tested": len(api_results),
                "security_issues": sum(len(result.security_issues) for result in api_results)
            },
            "brute_force": {
                "attempts_made": len(brute_force_results),
                "successful_attacks": len([r for r in brute_force_results if r.success])
            },
            "exploitation": {
                "exploits_attempted": len(exploit_results),
                "successful_exploits": len([r for r in exploit_results if r.success])
            }
        }
    
    def _generate_risk_assessment(self) -> Dict[str, Any]:
        """Generate risk assessment based on findings"""
        vulnerabilities = self.get_vulnerability_results()
        
        # Calculate risk score
        risk_score = 0
        for vuln in vulnerabilities:
            if vuln.severity == SeverityLevel.CRITICAL:
                risk_score += 10
            elif vuln.severity == SeverityLevel.HIGH:
                risk_score += 7
            elif vuln.severity == SeverityLevel.MEDIUM:
                risk_score += 4
            elif vuln.severity == SeverityLevel.LOW:
                risk_score += 2
            else:
                risk_score += 1
        
        # Determine risk level
        if risk_score >= 50:
            risk_level = "CRITICAL"
        elif risk_score >= 30:
            risk_level = "HIGH"
        elif risk_score >= 15:
            risk_level = "MEDIUM"
        elif risk_score >= 5:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "recommendations": self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        vulnerabilities = self.get_vulnerability_results()
        
        # Check for critical vulnerabilities
        critical_vulns = [v for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL]
        if critical_vulns:
            recommendations.append("Immediately patch critical vulnerabilities")
        
        # Check for high severity vulnerabilities
        high_vulns = [v for v in vulnerabilities if v.severity == SeverityLevel.HIGH]
        if high_vulns:
            recommendations.append("Prioritize patching high-severity vulnerabilities")
        
        # Check for brute force success
        brute_force_results = self.get_brute_force_results()
        successful_attacks = [r for r in brute_force_results if r.success]
        if successful_attacks:
            recommendations.append("Implement stronger authentication mechanisms")
        
        # Check for successful exploits
        exploit_results = self.get_exploit_results()
        successful_exploits = [r for r in exploit_results if r.success]
        if successful_exploits:
            recommendations.append("Review and harden exploited systems")
        
        return recommendations
    
    def save_session(self) -> bool:
        """Save current session to database"""
        try:
            # This would integrate with the database utilities
            # For now, we'll just return True
            return True
        except Exception as e:
            print(f"Error saving session: {e}")
            return False
    
    def load_session(self, session_id: str) -> bool:
        """Load session from database"""
        try:
            # This would load from database
            # For now, we'll just return True
            return True
        except Exception as e:
            print(f"Error loading session: {e}")
            return False
    
    def export_results(self, format_type: str = "json") -> str:
        """Export results in specified format"""
        if not self.current_session:
            return ""
        
        if format_type == "json":
            return json.dumps(asdict(self.current_session), default=str, indent=2)
        elif format_type == "csv":
            # Implement CSV export
            return self._export_csv()
        else:
            return ""

    def _export_csv(self) -> str:
        """Export results as CSV"""
        # Implement CSV export logic
        return "CSV export not implemented yet"

# Global results manager instance
results_manager = AssessmentResultsManager()

__all__ = [
    'AssessmentType',
    'SeverityLevel', 
    'NetworkHost',
    'PortInfo',
    'Vulnerability',
    'APITestResult',
    'BruteForceResult',
    'ExploitResult',
    'AssessmentResult',
    'AssessmentSession',
    'AssessmentResultsManager',
    'results_manager'
]
