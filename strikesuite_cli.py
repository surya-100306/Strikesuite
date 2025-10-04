#!/usr/bin/env python3
"""
StrikeSuite CLI - Command Line Interface
Advanced Cybersecurity Testing Framework
"""

import sys
import os
import logging
import argparse
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def setup_logging():
    """Configure application logging"""
    log_dir = project_root / "logs"
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / "application.log"),
            logging.StreamHandler()
        ]
    )

def test_installation():
    """Test if all modules can be imported"""
    print("Testing StrikeSuite installation...")
    
    try:
        from core.scanner import scan_ports
        print("✓ Scanner module loaded")
    except ImportError as e:
        print(f"✗ Scanner module failed: {e}")
        return False
    
    try:
        from core.api_tester import APITester
        print("✓ API Tester module loaded")
    except ImportError as e:
        print(f"✗ API Tester module failed: {e}")
        return False
    
    try:
        from core.vulnerability_scanner import VulnerabilityScanner
        print("✓ Vulnerability Scanner module loaded")
    except ImportError as e:
        print(f"✗ Vulnerability Scanner module failed: {e}")
        return False
    
    try:
        from utils.db_utils import init_db
        print("✓ Database utilities loaded")
    except ImportError as e:
        print(f"✗ Database utilities failed: {e}")
        return False
    
    return True

def run_port_scan(target, ports):
    """Run port scan"""
    print(f"Scanning {target} on ports {ports}")
    
    try:
        from core.scanner import scan_ports
        results = scan_ports(target, ports)
        
        print("\nPort Scan Results:")
        print("-" * 40)
        for port, is_open in results.items():
            status = "OPEN" if is_open else "CLOSED"
            print(f"Port {port}: {status}")
        
        return results
    except Exception as e:
        print(f"Port scan failed: {e}")
        return None

def run_vulnerability_scan(target):
    """Run vulnerability scan"""
    print(f"Scanning {target} for vulnerabilities")
    
    try:
        from core.vulnerability_scanner import VulnerabilityScanner
        scanner = VulnerabilityScanner()
        
        # Create target list - handle URLs properly
        if target.startswith(('http://', 'https://')):
            # Extract hostname and port from URL
            from urllib.parse import urlparse
            parsed = urlparse(target)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            service = 'https' if parsed.scheme == 'https' else 'http'
            targets = [{'hostname': target, 'port': port, 'service': service}]
        else:
            # Regular hostname/IP
            targets = [{'hostname': target, 'port': 80, 'service': 'http'}]
        
        results = scanner.comprehensive_scan(targets)
        
        print("\nVulnerability Scan Results:")
        print("-" * 40)
        for target_result in results.get('targets', []):
            vulnerabilities = target_result.get('vulnerabilities', [])
            if vulnerabilities:
                for vuln in vulnerabilities:
                    print(f"• {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}")
                    print(f"  {vuln.get('description', 'No description')}")
            else:
                print("No vulnerabilities found")
        
        return results
    except Exception as e:
        print(f"Vulnerability scan failed: {e}")
        return None

def run_api_test(target):
    """Run API security test"""
    print(f"Testing API security for {target}")
    
    try:
        from core.api_tester import APITester
        tester = APITester(target)
        
        # Test common endpoints
        endpoints = [f"{target}/api/users", f"{target}/api/admin"]
        results = tester.comprehensive_test(endpoints)
        
        print("\nAPI Security Test Results:")
        print("-" * 40)
        for test in results.get('tests', []):
            vulnerabilities = test.get('vulnerabilities', [])
            if vulnerabilities:
                for vuln in vulnerabilities:
                    print(f"• {vuln.get('issue', 'Unknown')} - {vuln.get('severity', 'Unknown')}")
            else:
                print(f"✓ {test.get('test_name', 'Unknown test')} - No issues found")
        
        return results
    except Exception as e:
        print(f"API test failed: {e}")
        return None

def run_advanced_port_scan(target, ports, options):
    """Run advanced port scan"""
    print(f"Running advanced port scan on {target}")
    
    try:
        from core.scanner import NetworkScanner
        scanner = NetworkScanner()
        
        # Prepare scan options
        scan_options = {
            'scan_type': 'tcp_connect',
            'ports': ports,
            'os_detection': options.get('os_detection', False),
            'service_detection': options.get('service_detection', False),
            'vulnerability_scan': options.get('vulnerability_scan', False),
            'stealth_mode': options.get('stealth', False)
        }
        
        results = scanner.advanced_port_scan(target, scan_options)
        
        print("\nAdvanced Port Scan Results:")
        print("-" * 40)
        if 'open_ports' in results:
            for port_info in results['open_ports']:
                print(f"Port {port_info['port']}: {port_info['state']} - {port_info.get('service', 'Unknown')}")
        
        if 'os_info' in results and results['os_info']:
            print(f"\nOS Detection: {results['os_info']}")
        
        if 'vulnerabilities' in results and results['vulnerabilities']:
            print("\nVulnerabilities Found:")
            for vuln in results['vulnerabilities']:
                print(f"• {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}")
        
        return results
    except Exception as e:
        print(f"Advanced port scan failed: {e}")
        return None

def run_advanced_api_test(target, options):
    """Run advanced API test"""
    print(f"Running advanced API test on {target}")
    
    try:
        from core.api_tester import APITester
        tester = APITester(target, advanced_mode=True, stealth_mode=options.get('stealth', False))
        
        # Prepare test options
        test_options = {
            'test_depth': options.get('depth', 'standard'),
            'stealth_mode': options.get('stealth', False),
            'fuzzing': options.get('fuzzing', False),
            'parameter_pollution': options.get('parameter_pollution', False),
            'jwt_analysis': options.get('jwt_analysis', False),
            'rate_limit_bypass': options.get('rate_limit_bypass', False)
        }
        
        # Test common endpoints
        endpoints = [f"{target}/api/users", f"{target}/api/admin", f"{target}/api/data"]
        results = tester.advanced_api_test(endpoints, test_options)
        
        print("\nAdvanced API Test Results:")
        print("-" * 40)
        if 'summary' in results:
            summary = results['summary']
            print(f"Total Tests: {summary.get('total_tests', 0)}")
            print(f"Vulnerabilities Found: {summary.get('vulnerabilities_found', 0)}")
            print(f"Risk Score: {summary.get('risk_score', 0)}/10")
        
        if 'vulnerabilities' in results:
            for vuln in results['vulnerabilities']:
                print(f"• {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}")
        
        return results
    except Exception as e:
        print(f"Advanced API test failed: {e}")
        return None

def run_advanced_brute_force(target, options):
    """Run advanced brute force attack"""
    print(f"Running advanced brute force attack on {target}")
    
    try:
        from core.brute_forcer import BruteForcer
        brute_forcer = BruteForcer()
        
        # Prepare brute force options
        brute_options = {
            'technique': 'intelligent',
            'attack_mode': 'normal',
            'wordlist_category': 'common',
            'pattern_matching': True,
            'rate_limit_detection': True,
            'max_attempts': 1000
        }
        
        # Add custom wordlists if provided
        if options.get('wordlist'):
            brute_options['custom_wordlist'] = options['wordlist']
        if options.get('username_list'):
            brute_options['username_list'] = options['username_list']
        if options.get('password_list'):
            brute_options['password_list'] = options['password_list']
        
        results = brute_forcer.advanced_brute_force(target, brute_options)
        
        print("\nAdvanced Brute Force Results:")
        print("-" * 40)
        if 'found_credentials' in results:
            for cred in results['found_credentials']:
                print(f"✓ Found: {cred.get('username', 'Unknown')}:{cred.get('password', 'Unknown')}")
        
        if 'statistics' in results:
            stats = results['statistics']
            print(f"Total Attempts: {stats.get('total_attempts', 0)}")
            print(f"Successful Logins: {stats.get('successful_logins', 0)}")
            print(f"Failed Attempts: {stats.get('failed_attempts', 0)}")
        
        return results
    except Exception as e:
        print(f"Advanced brute force failed: {e}")
        return None

def run_advanced_exploitation(target, options):
    """Run advanced exploitation test"""
    print(f"Running advanced exploitation test on {target}")
    
    try:
        from core.exploit_module import ExploitModule
        exploit = ExploitModule(advanced_mode=True, stealth_mode=options.get('stealth', False))
        
        # Prepare exploitation options
        exploit_options = {
            'test_depth': options.get('depth', 'standard'),
            'stealth_mode': options.get('stealth', False),
            'payload_generation': options.get('payload_generation', False),
            'evasion_techniques': options.get('evasion_techniques', False),
            'exploit_chaining': options.get('exploit_chaining', False)
        }
        
        results = exploit.advanced_exploitation_test(target, exploit_options)
        
        print("\nAdvanced Exploitation Results:")
        print("-" * 40)
        if 'summary' in results:
            summary = results['summary']
            print(f"Total Tests: {summary.get('total_tests', 0)}")
            print(f"Successful Exploits: {summary.get('successful_exploits', 0)}")
            print(f"Risk Score: {summary.get('risk_score', 0)}/10")
        
        if 'vulnerabilities' in results:
            for vuln in results['vulnerabilities']:
                print(f"• {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}")
        
        return results
    except Exception as e:
        print(f"Advanced exploitation failed: {e}")
        return None

def run_advanced_post_exploitation(target, options):
    """Run advanced post-exploitation analysis"""
    print(f"Running advanced post-exploitation analysis on {target}")
    
    try:
        from core.post_exploitation import PostExploitation
        post_exploit = PostExploitation(advanced_mode=True, stealth_mode=options.get('stealth', False))
        
        # Prepare post-exploitation options
        post_options = {
            'analysis_depth': options.get('depth', 'standard'),
            'stealth_mode': options.get('stealth', False),
            'privilege_escalation': options.get('privilege_escalation', False),
            'persistence_analysis': options.get('persistence_analysis', False),
            'lateral_movement': options.get('lateral_movement', False)
        }
        
        results = post_exploit.advanced_post_exploitation(target, post_options)
        
        print("\nAdvanced Post-Exploitation Results:")
        print("-" * 40)
        if 'summary' in results:
            summary = results['summary']
            print(f"Total Categories: {summary.get('total_categories', 0)}")
            print(f"Critical Findings: {summary.get('critical_findings', 0)}")
            print(f"Risk Score: {summary.get('risk_score', 0)}/10")
        
        return results
    except Exception as e:
        print(f"Advanced post-exploitation failed: {e}")
        return None

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description='StrikeSuite v1.0 - Advanced Penetration Testing Toolkit')
    parser.add_argument('--target', '-t', help='Target to scan (IP address or hostname)')
    parser.add_argument('--ports', '-p', default='22,80,443,8080', help='Ports to scan (comma-separated)')
    parser.add_argument('--scan-type', '-s', choices=['port', 'vuln', 'api', 'brute', 'exploit', 'post-exploit', 'all'], 
                       default='all', help='Type of scan to perform')
    parser.add_argument('--test', action='store_true', help='Test installation')
    
    # Advanced options
    parser.add_argument('--advanced', action='store_true', help='Enable advanced scanning features')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    parser.add_argument('--depth', choices=['quick', 'standard', 'deep', 'comprehensive'], 
                       default='standard', help='Scan depth level')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads for parallel operations')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout in seconds')
    
    # Advanced scan options
    parser.add_argument('--os-detection', action='store_true', help='Enable OS fingerprinting')
    parser.add_argument('--service-detection', action='store_true', help='Enable service detection')
    parser.add_argument('--vulnerability-scan', action='store_true', help='Enable vulnerability scanning')
    parser.add_argument('--exploit-verification', action='store_true', help='Enable exploit verification')
    parser.add_argument('--false-positive-reduction', action='store_true', help='Enable false positive reduction')
    
    # API testing options
    parser.add_argument('--fuzzing', action='store_true', help='Enable API fuzzing')
    parser.add_argument('--parameter-pollution', action='store_true', help='Enable parameter pollution testing')
    parser.add_argument('--jwt-analysis', action='store_true', help='Enable JWT security analysis')
    parser.add_argument('--rate-limit-bypass', action='store_true', help='Enable rate limit bypass testing')
    
    # Brute force options
    parser.add_argument('--brute-force', action='store_true', help='Enable brute force attacks')
    parser.add_argument('--wordlist', help='Path to custom wordlist file')
    parser.add_argument('--username-list', help='Path to username list file')
    parser.add_argument('--password-list', help='Path to password list file')
    
    # Exploitation options
    parser.add_argument('--exploitation', action='store_true', help='Enable exploitation testing')
    parser.add_argument('--payload-generation', action='store_true', help='Enable advanced payload generation')
    parser.add_argument('--evasion-techniques', action='store_true', help='Enable evasion techniques')
    parser.add_argument('--exploit-chaining', action='store_true', help='Enable exploit chaining')
    
    # Post-exploitation options
    parser.add_argument('--post-exploitation', action='store_true', help='Enable post-exploitation analysis')
    parser.add_argument('--privilege-escalation', action='store_true', help='Enable privilege escalation analysis')
    parser.add_argument('--persistence-analysis', action='store_true', help='Enable persistence analysis')
    parser.add_argument('--lateral-movement', action='store_true', help='Enable lateral movement analysis')
    
    # Output options
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--format', choices=['json', 'xml', 'csv', 'html', 'pdf'], 
                       default='json', help='Output format')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging()
    logger = logging.getLogger(__name__)
    
    print("StrikeSuite v1.0 - Advanced Penetration Testing Toolkit")
    print("=" * 60)
    
    # Test installation if requested
    if args.test:
        if test_installation():
            print("\n✓ Installation test passed!")
        else:
            print("\n✗ Installation test failed!")
            sys.exit(1)
        return
    
    # Check if target is provided
    if not args.target:
        print("Error: Target is required. Use --target <ip_or_hostname>")
        print("Example: python strikesuite_cli.py --target 192.168.1.1")
        sys.exit(1)
    
    # Parse ports
    try:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    except ValueError:
        print("Error: Invalid port format. Use comma-separated numbers (e.g., 22,80,443)")
        sys.exit(1)
    
    print(f"Target: {args.target}")
    print(f"Ports: {ports}")
    print(f"Scan Type: {args.scan_type}")
    print("-" * 60)
    
    # Initialize database
    try:
        from utils.db_utils import init_db
        init_db()
        print("✓ Database initialized")
    except Exception as e:
        print(f"⚠ Database initialization failed: {e}")
    
    # Prepare options dictionary
    options = {
        'advanced': args.advanced,
        'stealth': args.stealth,
        'depth': args.depth,
        'threads': args.threads,
        'timeout': args.timeout,
        'os_detection': args.os_detection,
        'service_detection': args.service_detection,
        'vulnerability_scan': args.vulnerability_scan,
        'exploit_verification': args.exploit_verification,
        'false_positive_reduction': args.false_positive_reduction,
        'fuzzing': args.fuzzing,
        'parameter_pollution': args.parameter_pollution,
        'jwt_analysis': args.jwt_analysis,
        'rate_limit_bypass': args.rate_limit_bypass,
        'wordlist': args.wordlist,
        'username_list': args.username_list,
        'password_list': args.password_list,
        'payload_generation': args.payload_generation,
        'evasion_techniques': args.evasion_techniques,
        'exploit_chaining': args.exploit_chaining,
        'privilege_escalation': args.privilege_escalation,
        'persistence_analysis': args.persistence_analysis,
        'lateral_movement': args.lateral_movement
    }
    
    # Run scans based on type
    if args.scan_type in ['port', 'all']:
        if args.advanced:
            run_advanced_port_scan(args.target, ports, options)
        else:
            run_port_scan(args.target, ports)
    
    if args.scan_type in ['vuln', 'all']:
        run_vulnerability_scan(args.target)
    
    if args.scan_type in ['api', 'all']:
        if args.advanced:
            run_advanced_api_test(args.target, options)
        else:
            run_api_test(args.target)
    
    if args.scan_type in ['brute', 'all']:
        if args.advanced:
            run_advanced_brute_force(args.target, options)
        elif args.brute_force:
            run_advanced_brute_force(args.target, options)
    
    if args.scan_type in ['exploit', 'all']:
        if args.advanced or args.exploitation:
            run_advanced_exploitation(args.target, options)
    
    if args.scan_type in ['post-exploit', 'all']:
        if args.advanced or args.post_exploitation:
            run_advanced_post_exploitation(args.target, options)
    
    print("\n" + "=" * 60)
    print("Scan completed!")

if __name__ == "__main__":
    main()
