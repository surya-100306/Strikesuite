#!/usr/bin/env python3
"""
Report Generator
Professional PDF and HTML report generation
"""

import json
import time
import os
from typing import Dict, List, Optional
import logging
from datetime import datetime

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logging.warning("ReportLab not available. PDF generation disabled.")

class ReportGenerator:
    """
    Professional report generation for security assessments
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.styles = None
        if REPORTLAB_AVAILABLE:
            self.styles = getSampleStyleSheet()
            self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom styles for reports"""
        if not REPORTLAB_AVAILABLE:
            return
            
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkred
        ))
        
        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkblue
        ))
        
        # Vulnerability style
        self.styles.add(ParagraphStyle(
            name='Vulnerability',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=6,
            leftIndent=20,
            textColor=colors.darkred
        ))
        
        # Recommendation style
        self.styles.add(ParagraphStyle(
            name='Recommendation',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=6,
            leftIndent=20,
            textColor=colors.darkgreen
        ))
    
    def generate_pdf_report(self, scan_results: Dict, output_path: str = None) -> str:
        """
        Generate PDF report from scan results
        
        Args:
            scan_results: Dictionary containing scan results
            output_path: Output file path (optional)
            
        Returns:
            Path to generated PDF file
        """
        if not REPORTLAB_AVAILABLE:
            self.logger.error("ReportLab not available. Cannot generate PDF.")
            return ""
        
        if output_path is None:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_path = f"reports/generated/security_report_{timestamp}.pdf"
        
        try:
            # Ensure directory exists
            output_dir = os.path.dirname(output_path)
            if output_dir:  # Only create directory if path is not empty
                os.makedirs(output_dir, exist_ok=True)
            
            # Create PDF document
            doc = SimpleDocTemplate(output_path, pagesize=A4)
            story = []
            
            # Title page
            story.append(Paragraph("StrikeSuite Security Assessment Report", 
                                 self.styles['CustomTitle']))
            story.append(Spacer(1, 20))
            
            # Report metadata
            metadata = [
                ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['Assessment Tool:', 'StrikeSuite v1.0'],
                ['Target(s):', scan_results.get('target', 'N/A')],
                ['Scan Duration:', scan_results.get('scan_time', 'N/A')]
            ]
            
            metadata_table = Table(metadata, colWidths=[2*inch, 4*inch])
            metadata_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('BACKGROUND', (1, 0), (1, -1), colors.beige),
            ]))
            
            story.append(metadata_table)
            story.append(Spacer(1, 20))
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", self.styles['CustomSubtitle']))
            story.append(Paragraph(
                self._generate_executive_summary(scan_results),
                self.styles['Normal']
            ))
            story.append(Spacer(1, 20))
            
            # Vulnerability Summary
            story.append(Paragraph("Vulnerability Summary", self.styles['CustomSubtitle']))
            vuln_summary = self._generate_vulnerability_summary(scan_results)
            story.append(vuln_summary)
            story.append(Spacer(1, 20))
            
            # Network Scan Results
            if scan_results.get('network_scans'):
                story.append(Paragraph("Network Scan Results", self.styles['CustomSubtitle']))
                network_results = self._generate_network_scan_results(scan_results)
                story.extend(network_results)
                story.append(Spacer(1, 20))
            
            # Vulnerability Scan Results
            if scan_results.get('vulnerability_scans'):
                story.append(Paragraph("Vulnerability Scan Results", self.styles['CustomSubtitle']))
                vuln_results = self._generate_vulnerability_scan_results(scan_results)
                story.extend(vuln_results)
                story.append(Spacer(1, 20))
            
            # API Test Results
            if scan_results.get('api_tests'):
                story.append(Paragraph("API Security Test Results", self.styles['CustomSubtitle']))
                api_results = self._generate_api_test_results(scan_results)
                story.extend(api_results)
                story.append(Spacer(1, 20))
            
            # Brute Force Results
            if scan_results.get('brute_force_results'):
                story.append(Paragraph("Brute Force Test Results", self.styles['CustomSubtitle']))
                brute_results = self._generate_brute_force_results(scan_results)
                story.extend(brute_results)
                story.append(Spacer(1, 20))
            
            # Exploitation Results
            if scan_results.get('exploitation_results'):
                story.append(Paragraph("Exploitation Results", self.styles['CustomSubtitle']))
                exploit_results = self._generate_exploitation_results(scan_results)
                story.extend(exploit_results)
                story.append(Spacer(1, 20))
            
            # Detailed Findings
            story.append(Paragraph("Detailed Findings", self.styles['CustomSubtitle']))
            findings = self._generate_detailed_findings(scan_results)
            story.extend(findings)
            story.append(Spacer(1, 20))
            
            # Recommendations
            story.append(Paragraph("Recommendations", self.styles['CustomSubtitle']))
            recommendations = self._generate_recommendations(scan_results)
            story.extend(recommendations)
            story.append(Spacer(1, 20))
            
            # Technical Details
            story.append(Paragraph("Technical Details", self.styles['CustomSubtitle']))
            tech_details = self._generate_technical_details(scan_results)
            story.extend(tech_details)
            
            # Build PDF
            doc.build(story)
            self.logger.info(f"PDF report generated: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error generating PDF report: {e}")
            return ""
    
    def generate_html_report(self, scan_results: Dict, output_path: str = None) -> str:
        """
        Generate HTML report from scan results
        
        Args:
            scan_results: Dictionary containing scan results
            output_path: Output file path (optional)
            
        Returns:
            Path to generated HTML file
        """
        if output_path is None:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_path = f"reports/generated/security_report_{timestamp}.html"
        
        try:
            # Ensure directory exists
            output_dir = os.path.dirname(output_path)
            if output_dir:  # Only create directory if path is not empty
                os.makedirs(output_dir, exist_ok=True)
            
            html_content = self._generate_html_content(scan_results)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML report generated: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {e}")
            return ""
    
    def _generate_executive_summary(self, scan_results: Dict) -> str:
        """Generate executive summary text"""
        summary = "This security assessment was conducted using StrikeSuite v1.0, "
        summary += "an advanced penetration testing toolkit. The assessment "
        summary += "identified several security vulnerabilities and provided "
        summary += "recommendations for remediation.\n\n"
        
        # Add vulnerability counts
        total_vulns = scan_results.get('summary', {}).get('total_vulnerabilities', 0)
        critical_vulns = scan_results.get('summary', {}).get('critical_count', 0)
        high_vulns = scan_results.get('summary', {}).get('high_count', 0)
        
        summary += f"Total vulnerabilities found: {total_vulns}\n"
        summary += f"Critical vulnerabilities: {critical_vulns}\n"
        summary += f"High severity vulnerabilities: {high_vulns}\n\n"
        
        summary += "Immediate action is recommended to address critical and high "
        summary += "severity vulnerabilities to reduce the risk of security breaches."
        
        return summary
    
    def _generate_vulnerability_summary(self, scan_results: Dict):
        """Generate vulnerability summary table"""
        if not REPORTLAB_AVAILABLE:
            return Paragraph("ReportLab not available", self.styles['Normal'])
        
        # Create vulnerability summary table
        vuln_data = [['Severity', 'Count', 'Percentage']]
        
        summary = scan_results.get('summary', {})
        total_vulns = summary.get('total_vulnerabilities', 0)
        
        if total_vulns > 0:
            critical = summary.get('critical_count', 0)
            high = summary.get('high_count', 0)
            medium = summary.get('medium_count', 0)
            low = summary.get('low_count', 0)
            
            vuln_data.extend([
                ['Critical', str(critical), f"{(critical/total_vulns)*100:.1f}%"],
                ['High', str(high), f"{(high/total_vulns)*100:.1f}%"],
                ['Medium', str(medium), f"{(medium/total_vulns)*100:.1f}%"],
                ['Low', str(low), f"{(low/total_vulns)*100:.1f}%"],
                ['Total', str(total_vulns), '100.0%']
            ])
        else:
            vuln_data.append(['No vulnerabilities found', '0', '0%'])
        
        vuln_table = Table(vuln_data, colWidths=[1.5*inch, 1*inch, 1*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        return vuln_table
    
    def _generate_detailed_findings(self, scan_results: Dict) -> List:
        """Generate detailed findings section"""
        findings = []
        
        if not REPORTLAB_AVAILABLE:
            return [Paragraph("ReportLab not available", self.styles['Normal'])]
        
        # Process all scan results
        all_findings = []
        
        # Add network scan results
        network_scans = scan_results.get('network_scans', [])
        for scan in network_scans:
            all_findings.append({
                'type': 'Network Scan',
                'target': scan.get('target', 'Unknown'),
                'port': scan.get('port', 'Unknown'),
                'service': scan.get('service', 'Unknown'),
                'status': scan.get('status', 'Unknown'),
                'banner': scan.get('banner', 'N/A'),
                'open_ports': scan.get('open_ports', []),
                'findings': scan.get('findings', [])
            })
        
        # Add vulnerability scan results
        vuln_scans = scan_results.get('vulnerability_scans', [])
        for scan in vuln_scans:
            all_findings.append({
                'type': 'Vulnerability Scan',
                'target': scan.get('target', 'Unknown'),
                'port': scan.get('port', 'Unknown'),
                'service': scan.get('service', 'Unknown'),
                'vulnerabilities': scan.get('vulnerabilities', []),
                'ssl_info': scan.get('ssl_info', {}),
                'headers': scan.get('headers', {}),
                'findings': scan.get('findings', [])
            })
        
        # Add API test results
        api_tests = scan_results.get('api_tests', [])
        for test in api_tests:
            all_findings.append({
                'type': 'API Security Test',
                'target': test.get('target', 'Unknown'),
                'endpoint': test.get('endpoint', 'Unknown'),
                'method': test.get('method', 'Unknown'),
                'status_code': test.get('status_code', 'Unknown'),
                'vulnerabilities': test.get('vulnerabilities', []),
                'findings': test.get('findings', [])
            })
        
        # Add brute force results
        brute_results = scan_results.get('brute_force_results', [])
        for result in brute_results:
            all_findings.append({
                'type': 'Brute Force Test',
                'target': result.get('target', 'Unknown'),
                'port': result.get('port', 'Unknown'),
                'service': result.get('service', 'Unknown'),
                'attempts': result.get('attempts', 0),
                'successful_credentials': result.get('successful_credentials', []),
                'findings': result.get('findings', [])
            })
        
        # Add exploitation results
        exploit_results = scan_results.get('exploitation_results', [])
        for result in exploit_results:
            all_findings.append({
                'type': 'Exploitation',
                'target': result.get('target', 'Unknown'),
                'port': result.get('port', 'Unknown'),
                'service': result.get('service', 'Unknown'),
                'exploit_used': result.get('exploit_used', 'Unknown'),
                'success': result.get('success', False),
                'payload': result.get('payload', 'N/A'),
                'findings': result.get('findings', [])
            })
        
        # Process each finding
        for i, finding in enumerate(all_findings, 1):
            findings.append(Paragraph(f"{i}. {finding['type']} - {finding['target']}", self.styles['Heading3']))
            
            # Add scan-specific details
            if finding['type'] == 'Network Scan':
                findings.append(Paragraph(f"Port: {finding['port']}", self.styles['Normal']))
                findings.append(Paragraph(f"Service: {finding['service']}", self.styles['Normal']))
                findings.append(Paragraph(f"Status: {finding['status']}", self.styles['Normal']))
                if finding['banner'] != 'N/A':
                    findings.append(Paragraph(f"Banner: {finding['banner']}", self.styles['Normal']))
                if finding['open_ports']:
                    findings.append(Paragraph(f"Open Ports: {', '.join(map(str, finding['open_ports']))}", self.styles['Normal']))
            
            elif finding['type'] == 'Vulnerability Scan':
                findings.append(Paragraph(f"Port: {finding['port']}", self.styles['Normal']))
                findings.append(Paragraph(f"Service: {finding['service']}", self.styles['Normal']))
                vulnerabilities = finding.get('vulnerabilities', [])
                if vulnerabilities:
                    findings.append(Paragraph(f"Vulnerabilities Found: {len(vulnerabilities)}", self.styles['Normal']))
                    for j, vuln in enumerate(vulnerabilities, 1):
                        vuln_text = f"  {j}. {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}"
                        findings.append(Paragraph(vuln_text, self.styles['Vulnerability']))
                        if vuln.get('description'):
                            findings.append(Paragraph(f"     Description: {vuln['description']}", self.styles['Normal']))
                        if vuln.get('cve'):
                            findings.append(Paragraph(f"     CVE: {vuln['cve']}", self.styles['Normal']))
                        if vuln.get('remediation'):
                            findings.append(Paragraph(f"     Remediation: {vuln['remediation']}", self.styles['Recommendation']))
                else:
                    findings.append(Paragraph("No vulnerabilities found", self.styles['Normal']))
            
            elif finding['type'] == 'API Security Test':
                findings.append(Paragraph(f"Endpoint: {finding['endpoint']}", self.styles['Normal']))
                findings.append(Paragraph(f"Method: {finding['method']}", self.styles['Normal']))
                findings.append(Paragraph(f"Status Code: {finding['status_code']}", self.styles['Normal']))
                vulnerabilities = finding.get('vulnerabilities', [])
                if vulnerabilities:
                    findings.append(Paragraph(f"Vulnerabilities Found: {len(vulnerabilities)}", self.styles['Normal']))
                    for j, vuln in enumerate(vulnerabilities, 1):
                        vuln_text = f"  {j}. {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}"
                        findings.append(Paragraph(vuln_text, self.styles['Vulnerability']))
                        if vuln.get('description'):
                            findings.append(Paragraph(f"     Description: {vuln['description']}", self.styles['Normal']))
                else:
                    findings.append(Paragraph("No vulnerabilities found", self.styles['Normal']))
            
            elif finding['type'] == 'Brute Force Test':
                findings.append(Paragraph(f"Port: {finding['port']}", self.styles['Normal']))
                findings.append(Paragraph(f"Service: {finding['service']}", self.styles['Normal']))
                findings.append(Paragraph(f"Attempts: {finding['attempts']}", self.styles['Normal']))
                successful_creds = finding.get('successful_credentials', [])
                if successful_creds:
                    findings.append(Paragraph(f"Successful Credentials: {len(successful_creds)}", self.styles['Normal']))
                    for j, cred in enumerate(successful_creds, 1):
                        findings.append(Paragraph(f"  {j}. {cred.get('username', 'Unknown')}:{cred.get('password', 'Unknown')}", self.styles['Normal']))
                else:
                    findings.append(Paragraph("No successful credentials found", self.styles['Normal']))
            
            elif finding['type'] == 'Exploitation':
                findings.append(Paragraph(f"Port: {finding['port']}", self.styles['Normal']))
                findings.append(Paragraph(f"Service: {finding['service']}", self.styles['Normal']))
                findings.append(Paragraph(f"Exploit Used: {finding['exploit_used']}", self.styles['Normal']))
                findings.append(Paragraph(f"Success: {'Yes' if finding['success'] else 'No'}", self.styles['Normal']))
                if finding['payload'] != 'N/A':
                    findings.append(Paragraph(f"Payload: {finding['payload']}", self.styles['Normal']))
            
            findings.append(Spacer(1, 20))
        
        return findings
    
    def _generate_recommendations(self, scan_results: Dict) -> List:
        """Generate recommendations section"""
        recommendations = []
        
        if not REPORTLAB_AVAILABLE:
            return [Paragraph("ReportLab not available", self.styles['Normal'])]
        
        # General recommendations
        general_recs = [
            "Implement regular security updates and patches",
            "Use strong authentication mechanisms",
            "Implement network segmentation",
            "Regular security awareness training for staff",
            "Implement monitoring and logging",
            "Regular security assessments and penetration testing"
        ]
        
        for i, rec in enumerate(general_recs, 1):
            recommendations.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))
            recommendations.append(Spacer(1, 6))
        
        return recommendations
    
    def _generate_technical_details(self, scan_results: Dict) -> List:
        """Generate technical details section"""
        details = []
        
        if not REPORTLAB_AVAILABLE:
            return [Paragraph("ReportLab not available", self.styles['Normal'])]
        
        # Scan configuration
        details.append(Paragraph("Scan Configuration", self.styles['Heading3']))
        config_info = [
            f"Scan Time: {scan_results.get('scan_time', 'N/A')}",
            f"Target: {scan_results.get('target', 'N/A')}",
            f"Tool Version: StrikeSuite v1.0"
        ]
        
        for info in config_info:
            details.append(Paragraph(info, self.styles['Normal']))
            details.append(Spacer(1, 6))
        
        # Raw scan data (truncated)
        details.append(Paragraph("Raw Scan Data", self.styles['Heading3']))
        details.append(Paragraph(
            "Detailed scan data is available in the JSON output files. "
            "This includes complete vulnerability details, network scan results, "
            "and technical evidence for each finding.",
            self.styles['Normal']
        ))
        
        return details
    
    def _generate_html_content(self, scan_results: Dict) -> str:
        """Generate HTML report content"""
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StrikeSuite Security Assessment Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
        }}
        .header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
            border-radius: 5px;
        }}
        .content {{
            background-color: white;
            padding: 30px;
            margin-top: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .vulnerability {{
            background-color: #ffebee;
            border-left: 4px solid #f44336;
            padding: 10px;
            margin: 10px 0;
        }}
        .recommendation {{
            background-color: #e8f5e8;
            border-left: 4px solid #4caf50;
            padding: 10px;
            margin: 10px 0;
        }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; font-weight: bold; }}
        .low {{ color: #388e3c; font-weight: bold; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>StrikeSuite Security Assessment Report</h1>
        <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="content">
        <h2>Executive Summary</h2>
        <p>{self._generate_executive_summary(scan_results)}</p>
        
        <h2>Vulnerability Summary</h2>
        {self._generate_html_vulnerability_summary(scan_results)}
        
        <h2>Detailed Findings</h2>
        {self._generate_html_detailed_findings(scan_results)}
        
        <h2>Recommendations</h2>
        {self._generate_html_recommendations(scan_results)}
        
        <h2>Technical Details</h2>
        <p>Detailed scan data is available in the JSON output files. This includes complete vulnerability details, network scan results, and technical evidence for each finding.</p>
    </div>
</body>
</html>
        """
        return html
    
    def _generate_html_vulnerability_summary(self, scan_results: Dict) -> str:
        """Generate HTML vulnerability summary table"""
        summary = scan_results.get('summary', {})
        total_vulns = summary.get('total_vulnerabilities', 0)
        
        if total_vulns > 0:
            critical = summary.get('critical_count', 0)
            high = summary.get('high_count', 0)
            medium = summary.get('medium_count', 0)
            low = summary.get('low_count', 0)
            
            html = """
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
                <tr>
                    <td class="critical">Critical</td>
                    <td>{}</td>
                    <td>{:.1f}%</td>
                </tr>
                <tr>
                    <td class="high">High</td>
                    <td>{}</td>
                    <td>{:.1f}%</td>
                </tr>
                <tr>
                    <td class="medium">Medium</td>
                    <td>{}</td>
                    <td>{:.1f}%</td>
                </tr>
                <tr>
                    <td class="low">Low</td>
                    <td>{}</td>
                    <td>{:.1f}%</td>
                </tr>
                <tr>
                    <td><strong>Total</strong></td>
                    <td><strong>{}</strong></td>
                    <td><strong>100.0%</strong></td>
                </tr>
            </table>
            """.format(
                critical, (critical/total_vulns)*100,
                high, (high/total_vulns)*100,
                medium, (medium/total_vulns)*100,
                low, (low/total_vulns)*100,
                total_vulns
            )
        else:
            html = "<p>No vulnerabilities found</p>"
        
        return html
    
    def _generate_html_detailed_findings(self, scan_results: Dict) -> str:
        """Generate HTML detailed findings"""
        html = ""
        targets = scan_results.get('targets', [])
        
        for target in targets:
            target_name = target.get('hostname', 'Unknown')
            html += f"<h3>Target: {target_name}</h3>"
            
            vulnerabilities = target.get('vulnerabilities', [])
            if vulnerabilities:
                for i, vuln in enumerate(vulnerabilities, 1):
                    severity_class = vuln.get('severity', 'medium').lower()
                    html += f"""
                    <div class="vulnerability">
                        <h4>{i}. {vuln.get('type', 'Unknown')} - <span class="{severity_class}">{vuln.get('severity', 'Unknown')}</span></h4>
                        <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
                        <p><strong>Recommendation:</strong> {vuln.get('recommendation', 'No recommendation available')}</p>
                    </div>
                    """
            else:
                html += "<p>No vulnerabilities found</p>"
        
        return html
    
    def _generate_html_recommendations(self, scan_results: Dict) -> str:
        """Generate HTML recommendations"""
        recommendations = [
            "Implement regular security updates and patches",
            "Use strong authentication mechanisms",
            "Implement network segmentation",
            "Regular security awareness training for staff",
            "Implement monitoring and logging",
            "Regular security assessments and penetration testing"
        ]
        
        html = "<ul>"
        for rec in recommendations:
            html += f"<li>{rec}</li>"
        html += "</ul>"
        
        return html
    
    def _generate_network_scan_results(self, scan_results: Dict) -> List:
        """Generate network scan results section"""
        findings = []
        
        if not REPORTLAB_AVAILABLE:
            return [Paragraph("ReportLab not available", self.styles['Normal'])]
        
        network_scans = scan_results.get('network_scans', [])
        
        for scan in network_scans:
            # Network scan summary
            scan_text = f"""
            <b>Target:</b> {scan.get('target', 'Unknown')}<br/>
            <b>Port:</b> {scan.get('port', 'Unknown')}<br/>
            <b>Service:</b> {scan.get('service', 'Unknown')}<br/>
            <b>Status:</b> {scan.get('status', 'Unknown')}<br/>
            <b>Banner:</b> {scan.get('banner', 'N/A')}<br/>
            <b>Open Ports:</b> {', '.join(map(str, scan.get('open_ports', [])))}
            """
            findings.append(Paragraph(scan_text, self.styles['Normal']))
            findings.append(Spacer(1, 12))
        
        return findings
    
    def _generate_vulnerability_scan_results(self, scan_results: Dict) -> List:
        """Generate vulnerability scan results section"""
        findings = []
        
        if not REPORTLAB_AVAILABLE:
            return [Paragraph("ReportLab not available", self.styles['Normal'])]
        
        vuln_scans = scan_results.get('vulnerability_scans', [])
        
        for scan in vuln_scans:
            # Vulnerability scan summary
            scan_text = f"""
            <b>Target:</b> {scan.get('target', 'Unknown')}<br/>
            <b>Port:</b> {scan.get('port', 'Unknown')}<br/>
            <b>Service:</b> {scan.get('service', 'Unknown')}<br/>
            <b>Vulnerabilities Found:</b> {len(scan.get('vulnerabilities', []))}
            """
            findings.append(Paragraph(scan_text, self.styles['Normal']))
            
            # List vulnerabilities
            for vuln in scan.get('vulnerabilities', []):
                vuln_text = f"""
                <b>Type:</b> {vuln.get('type', 'Unknown')}<br/>
                <b>Severity:</b> {vuln.get('severity', 'Unknown')}<br/>
                <b>Description:</b> {vuln.get('description', 'N/A')}<br/>
                <b>CVE:</b> {vuln.get('cve', 'N/A')}
                """
                findings.append(Paragraph(vuln_text, self.styles['Normal']))
                findings.append(Spacer(1, 8))
            
            findings.append(Spacer(1, 12))
        
        return findings
    
    def _generate_api_test_results(self, scan_results: Dict) -> List:
        """Generate API test results section"""
        findings = []
        
        if not REPORTLAB_AVAILABLE:
            return [Paragraph("ReportLab not available", self.styles['Normal'])]
        
        api_tests = scan_results.get('api_tests', [])
        
        for test in api_tests:
            # API test summary
            test_text = f"""
            <b>Target:</b> {test.get('target', 'Unknown')}<br/>
            <b>Endpoint:</b> {test.get('endpoint', 'Unknown')}<br/>
            <b>Method:</b> {test.get('method', 'Unknown')}<br/>
            <b>Status Code:</b> {test.get('status_code', 'Unknown')}<br/>
            <b>Vulnerabilities Found:</b> {len(test.get('vulnerabilities', []))}
            """
            findings.append(Paragraph(test_text, self.styles['Normal']))
            
            # List API vulnerabilities
            for vuln in test.get('vulnerabilities', []):
                vuln_text = f"""
                <b>Type:</b> {vuln.get('type', 'Unknown')}<br/>
                <b>Severity:</b> {vuln.get('severity', 'Unknown')}<br/>
                <b>Description:</b> {vuln.get('description', 'N/A')}
                """
                findings.append(Paragraph(vuln_text, self.styles['Normal']))
                findings.append(Spacer(1, 8))
            
            findings.append(Spacer(1, 12))
        
        return findings
    
    def _generate_brute_force_results(self, scan_results: Dict) -> List:
        """Generate brute force test results section"""
        findings = []
        
        if not REPORTLAB_AVAILABLE:
            return [Paragraph("ReportLab not available", self.styles['Normal'])]
        
        brute_results = scan_results.get('brute_force_results', [])
        
        for result in brute_results:
            # Brute force summary
            result_text = f"""
            <b>Target:</b> {result.get('target', 'Unknown')}<br/>
            <b>Port:</b> {result.get('port', 'Unknown')}<br/>
            <b>Service:</b> {result.get('service', 'Unknown')}<br/>
            <b>Attempts:</b> {result.get('attempts', 0)}<br/>
            <b>Successful Credentials:</b> {len(result.get('successful_credentials', []))}
            """
            findings.append(Paragraph(result_text, self.styles['Normal']))
            
            # List successful credentials
            for cred in result.get('successful_credentials', []):
                cred_text = f"""
                <b>Username:</b> {cred.get('username', 'Unknown')}<br/>
                <b>Password:</b> {cred.get('password', 'Unknown')}
                """
                findings.append(Paragraph(cred_text, self.styles['Normal']))
                findings.append(Spacer(1, 8))
            
            findings.append(Spacer(1, 12))
        
        return findings
    
    def _generate_exploitation_results(self, scan_results: Dict) -> List:
        """Generate exploitation results section"""
        findings = []
        
        if not REPORTLAB_AVAILABLE:
            return [Paragraph("ReportLab not available", self.styles['Normal'])]
        
        exploit_results = scan_results.get('exploitation_results', [])
        
        for result in exploit_results:
            # Exploitation summary
            result_text = f"""
            <b>Target:</b> {result.get('target', 'Unknown')}<br/>
            <b>Port:</b> {result.get('port', 'Unknown')}<br/>
            <b>Service:</b> {result.get('service', 'Unknown')}<br/>
            <b>Exploit Used:</b> {result.get('exploit_used', 'Unknown')}<br/>
            <b>Success:</b> {'Yes' if result.get('success', False) else 'No'}<br/>
            <b>Payload:</b> {result.get('payload', 'N/A')}
            """
            findings.append(Paragraph(result_text, self.styles['Normal']))
            findings.append(Spacer(1, 12))
        
        return findings
    
    def save_results(self, results: Dict, filename: str = None) -> str:
        """
        Save report generation results to JSON file
        
        Args:
            results: Report results dictionary
            filename: Output filename (optional)
            
        Returns:
            Path to saved file
        """
        if filename is None:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"report_generation_{timestamp}.json"
        
        filepath = f"logs/scan_logs/{filename}"
        
        try:
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2)
            self.logger.info(f"Results saved to {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
            return ""
    
    def generate_report(self, scan_data: List[Dict], config: Dict) -> str:
        """Generate comprehensive security report"""
        try:
            self.logger.info("Starting report generation...")
            
            # Prepare report data
            report_data = {
                'title': config.get('title', 'Security Assessment Report'),
                'client': config.get('client', ''),
                'date': config.get('date', datetime.now().strftime('%Y-%m-%d')),
                'assessor': config.get('assessor', ''),
                'template': config.get('template', 'Executive Summary Report'),
                'sections': config.get('sections', {}),
                'scan_data': scan_data,
                'generated_at': datetime.now().isoformat()
            }
            
            # Generate report based on format
            format_type = config.get('format', 'pdf').lower()
            
            if format_type == 'pdf':
                return self.generate_pdf_report(report_data)
            elif format_type == 'html':
                return self.generate_html_report(report_data)
            else:
                # Default to PDF
                return self.generate_pdf_report(report_data)
                
        except Exception as e:
            self.logger.error(f"Failed to generate report: {e}")
            return None
    
    def export_report(self, scan_data: List[Dict], output_path: str) -> bool:
        """Export report to specified path"""
        try:
            self.logger.info(f"Exporting report to {output_path}")
            
            # Determine format from file extension
            if output_path.lower().endswith('.pdf'):
                result = self.generate_pdf_report(scan_data, output_path)
            elif output_path.lower().endswith('.html'):
                result = self.generate_html_report(scan_data, output_path)
            else:
                # Default to JSON export
                result = self.save_results(scan_data, output_path)
            
            return result is not None
            
        except Exception as e:
            self.logger.error(f"Failed to export report: {e}")
            return False