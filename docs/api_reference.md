# StrikeSuite API Reference

## Core Modules API

### NetworkScanner

```python
from core.scanner import NetworkScanner

# Initialize scanner
scanner = NetworkScanner()

# Basic port scan
results = scanner.scan_ports(target, ports)

# Advanced port scan
scan_options = {
    'scan_type': 'tcp_connect',
    'ports': [22, 80, 443],
    'os_detection': True,
    'service_detection': True,
    'vulnerability_scan': True,
    'stealth_mode': False
}
results = scanner.advanced_port_scan(target, scan_options)
```

**Methods:**
- `scan_ports(target, ports)` - Basic port scanning
- `advanced_port_scan(target, options)` - Advanced scanning with options
- `scan_port(target, port)` - Single port scan

**Return Format:**
```python
{
    'target': '192.168.1.1',
    'open_ports': [
        {'port': 80, 'state': 'open', 'service': 'http'},
        {'port': 443, 'state': 'open', 'service': 'https'}
    ],
    'os_info': 'Linux 4.15.0',
    'vulnerabilities': [
        {'type': 'SQL Injection', 'severity': 'High'}
    ]
}
```

### VulnerabilityScanner

```python
from core.vulnerability_scanner import VulnerabilityScanner

# Initialize scanner
scanner = VulnerabilityScanner(scan_depth='standard', stealth_mode=False)

# Basic vulnerability scan
targets = [{'hostname': 'example.com', 'port': 80, 'service': 'http'}]
results = scanner.comprehensive_scan(targets)

# Advanced vulnerability scan
scan_options = {
    'os_fingerprinting': True,
    'service_fingerprinting': True,
    'exploit_verification': True,
    'false_positive_reduction': True,
    'custom_payloads': True
}
results = scanner.advanced_vulnerability_scan(targets, scan_options)
```

**Methods:**
- `comprehensive_scan(targets)` - Basic vulnerability scanning
- `advanced_vulnerability_scan(targets, options)` - Advanced scanning
- `scan_ssl_security(target)` - SSL/TLS security analysis
- `scan_http_security(target)` - HTTP security analysis

### APITester

```python
from core.api_tester import APITester

# Initialize tester
tester = APITester('https://api.example.com', advanced_mode=True, stealth_mode=False)

# Basic API test
endpoints = ['/api/users', '/api/admin']
results = tester.comprehensive_test(endpoints)

# Advanced API test
test_options = {
    'test_depth': 'comprehensive',
    'stealth_mode': False,
    'fuzzing': True,
    'parameter_pollution': True,
    'jwt_analysis': True,
    'rate_limit_bypass': True
}
results = tester.advanced_api_test(endpoints, test_options)
```

**Methods:**
- `comprehensive_test(endpoints)` - Basic API testing
- `advanced_api_test(endpoints, options)` - Advanced testing
- `test_authentication(endpoint)` - Authentication testing
- `test_authorization(endpoint)` - Authorization testing

### BruteForcer

```python
from core.brute_forcer import BruteForcer

# Initialize brute forcer
brute_forcer = BruteForcer()

# Basic brute force
results = brute_forcer.comprehensive_brute_force(target, service)

# Advanced brute force
brute_options = {
    'technique': 'intelligent',
    'attack_mode': 'stealth',
    'wordlist_category': 'common',
    'pattern_matching': True,
    'rate_limit_detection': True,
    'max_attempts': 1000
}
results = brute_forcer.advanced_brute_force(target, service, brute_options)
```

**Methods:**
- `comprehensive_brute_force(target, service)` - Basic brute force
- `advanced_brute_force(target, service, options)` - Advanced brute force
- `load_builtin_wordlists()` - Load built-in wordlists
- `generate_password_patterns()` - Generate password patterns

### ExploitModule

```python
from core.exploit_module import ExploitModule

# Initialize exploit module
exploit = ExploitModule(advanced_mode=True, stealth_mode=False)

# Basic exploit test
results = exploit.comprehensive_exploit_test(target)

# Advanced exploitation
exploit_options = {
    'test_depth': 'comprehensive',
    'stealth_mode': False,
    'payload_generation': True,
    'evasion_techniques': True,
    'exploit_chaining': True
}
results = exploit.advanced_exploitation_test(target, exploit_options)
```

**Methods:**
- `comprehensive_exploit_test(target)` - Basic exploitation testing
- `advanced_exploitation_test(target, options)` - Advanced exploitation
- `_advanced_web_shell_upload(target, options)` - Web shell testing
- `_advanced_sql_injection(target, options)` - SQL injection testing

### PostExploitation

```python
from core.post_exploitation import PostExploitation

# Initialize post-exploitation module
post_exploit = PostExploitation(advanced_mode=True, stealth_mode=False)

# Basic post-exploitation
results = post_exploit.comprehensive_enumeration(target, options)

# Advanced post-exploitation
post_options = {
    'analysis_depth': 'comprehensive',
    'stealth_mode': False,
    'privilege_escalation': True,
    'persistence_analysis': True,
    'lateral_movement': True
}
results = post_exploit.advanced_post_exploitation(target, post_options)
```

**Methods:**
- `comprehensive_enumeration(target, options)` - Basic enumeration
- `advanced_post_exploitation(target, options)` - Advanced analysis
- `_analyze_privilege_escalation(target)` - Privilege escalation analysis
- `_analyze_persistence(target)` - Persistence analysis

## GUI Components API

### MainWindow

```python
from gui.main_window import MainWindow
from PyQt5.QtWidgets import QApplication

# Create application
app = QApplication([])
window = MainWindow()
window.show()
app.exec_()
```

### Individual Tabs

```python
from gui.network_tab import NetworkTab
from gui.api_tab import APITab
from gui.vulnerability_tab import VulnerabilityTab

# Create tabs
network_tab = NetworkTab()
api_tab = APITab()
vuln_tab = VulnerabilityTab()
```

## Database API

```python
from utils.db_utils import init_db, get_db_manager

# Initialize database
init_db()

# Get database manager
db_manager = get_db_manager()

# Database operations
scan_history = db_manager.get_scan_history()
vulnerabilities = db_manager.get_vulnerabilities()
credentials = db_manager.get_credentials()
```

## Reporting API

```python
from core.reporter import ReportGenerator

# Initialize reporter
reporter = ReportGenerator()

# Generate PDF report
reporter.generate_pdf_report(scan_results, 'report.pdf')

# Generate HTML report
reporter.generate_html_report(scan_results, 'report.html')
```

## Plugin API

```python
from core.plugin_manager import PluginManager

# Initialize plugin manager
plugin_manager = PluginManager(advanced_mode=True)

# Advanced plugin execution
plugin_options = {
    'execution_mode': 'sequential',
    'hot_reload': True,
    'dependency_management': True,
    'plugin_chaining': True,
    'resource_management': True,
    'security_sandbox': True,
    'performance_monitoring': True,
    'error_recovery': True
}
results = plugin_manager.advanced_plugin_execution(plugin_options)
```

## CLI API

```python
import strikesuite_cli

# CLI functions
from strikesuite_cli import (
    run_advanced_port_scan,
    run_advanced_api_test,
    run_advanced_brute_force,
    run_advanced_exploitation,
    run_advanced_post_exploitation
)

# Example usage
options = {
    'advanced': True,
    'stealth': False,
    'depth': 'standard'
}
results = run_advanced_port_scan('192.168.1.1', [22, 80, 443], options)
```

## Error Handling

```python
try:
    scanner = NetworkScanner()
    results = scanner.advanced_port_scan(target, options)
except Exception as e:
    print(f"Scan failed: {e}")
    # Handle error appropriately
```

## Configuration Options

### Scan Options
```python
scan_options = {
    'scan_type': 'tcp_connect',  # tcp_connect, syn_stealth, udp, stealth
    'ports': [22, 80, 443],      # List of ports to scan
    'os_detection': True,         # Enable OS fingerprinting
    'service_detection': True,    # Enable service detection
    'vulnerability_scan': True,   # Enable vulnerability scanning
    'stealth_mode': False        # Enable stealth mode
}
```

### API Test Options
```python
test_options = {
    'test_depth': 'standard',     # quick, standard, deep, comprehensive
    'stealth_mode': False,        # Enable stealth mode
    'fuzzing': True,             # Enable fuzzing
    'parameter_pollution': True,  # Enable parameter pollution
    'jwt_analysis': True,        # Enable JWT analysis
    'rate_limit_bypass': True    # Enable rate limit bypass
}
```

### Brute Force Options
```python
brute_options = {
    'technique': 'intelligent',   # intelligent, dictionary, hybrid, mask, rule_based
    'attack_mode': 'normal',      # normal, stealth, aggressive, custom
    'wordlist_category': 'common', # common, defaults, technical, seasonal, company, brute_force
    'pattern_matching': True,     # Enable pattern matching
    'rate_limit_detection': True, # Enable rate limit detection
    'max_attempts': 1000         # Maximum attempts
}
```

## Return Value Formats

### Scan Results
```python
{
    'target': '192.168.1.1',
    'scan_type': 'advanced_port_scan',
    'timestamp': '2024-01-01T12:00:00Z',
    'open_ports': [
        {
            'port': 80,
            'state': 'open',
            'service': 'http',
            'version': 'Apache/2.4.41',
            'banner': 'HTTP/1.1 200 OK'
        }
    ],
    'os_info': {
        'os': 'Linux',
        'version': '4.15.0',
        'confidence': 0.85
    },
    'vulnerabilities': [
        {
            'type': 'SQL Injection',
            'severity': 'High',
            'description': 'SQL injection vulnerability found',
            'cve': 'CVE-2023-1234',
            'remediation': 'Update to latest version'
        }
    ],
    'summary': {
        'total_ports': 1000,
        'open_ports': 3,
        'closed_ports': 997,
        'filtered_ports': 0,
        'scan_duration': 45.2
    }
}
```

### Vulnerability Results
```python
{
    'targets': [
        {
            'hostname': 'example.com',
            'port': 80,
            'service': 'http',
            'vulnerabilities': [
                {
                    'type': 'XSS',
                    'severity': 'Medium',
                    'description': 'Cross-site scripting vulnerability',
                    'url': 'http://example.com/search',
                    'parameter': 'q',
                    'payload': '<script>alert("XSS")</script>',
                    'remediation': 'Implement input validation'
                }
            ]
        }
    ],
    'summary': {
        'total_targets': 1,
        'vulnerable_targets': 1,
        'total_vulnerabilities': 1,
        'critical': 0,
        'high': 0,
        'medium': 1,
        'low': 0,
        'info': 0
    }
}
```

---

*This API reference is maintained and updated regularly. For the latest version, please visit the project repository.*