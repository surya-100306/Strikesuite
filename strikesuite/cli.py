#!/usr/bin/env python3
"""
StrikeSuite CLI Interface
Command-line interface for the security testing framework
"""

import sys
import argparse
import logging
from pathlib import Path

def setup_cli_logging():
    """Setup logging for CLI mode"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def scan_command(args):
    """Handle scan command"""
    print(f"🔍 Scanning target: {args.target}")
    print(f"📋 Scan type: {args.type}")
    print(f"🔧 Options: {args.options}")
    
    # Import and use scanner
    try:
        from strikesuite.core import NetworkScanner
        scanner = NetworkScanner()
        
        if args.type == "network":
            results = scanner.network_scan(args.target)
            print(f"✅ Found {len(results.get('hosts', []))} hosts")
            for host in results.get('hosts', []):
                print(f"   📍 {host}")
        elif args.type == "ports":
            # Parse ports if provided as string
            if isinstance(args.ports, str):
                ports = [int(p.strip()) for p in args.ports.split(',')]
            else:
                ports = args.ports or [22, 80, 443, 8080]
            
            results = scanner.scan_ports(args.target, ports)
            open_ports = results.get('open_ports', [])
            print(f"✅ Found {len(open_ports)} open ports")
            for port_info in open_ports:
                if isinstance(port_info, dict):
                    print(f"   🔌 Port {port_info.get('port', 'unknown')}: {port_info.get('service', 'unknown')}")
                else:
                    print(f"   🔌 Port {port_info}")
        
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        return 1
    
    return 0

def test_command(args):
    """Handle test command"""
    print(f"🧪 Testing target: {args.target}")
    print(f"🔧 Test type: {args.type}")
    
    try:
        if args.type == "api":
            from strikesuite.core import APITester
            tester = APITester(args.target)
            # Test common API endpoints
            endpoints = [f"{args.target}/api/users", f"{args.target}/api/admin", f"{args.target}/api/data"]
            results = tester.comprehensive_test(endpoints)
            issues = results.get('issues', [])
            print(f"✅ API test completed: {len(issues)} issues found")
        elif args.type == "vulnerability":
            from strikesuite.core import VulnerabilityScanner
            scanner = VulnerabilityScanner()
            # Create target list for vulnerability scan
            targets = [{'hostname': args.target, 'port': 80, 'service': 'http'}]
            results = scanner.comprehensive_scan(targets)
            vulnerabilities = results.get('vulnerabilities', [])
            print(f"✅ Vulnerability scan completed: {len(vulnerabilities)} issues found")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return 1
    
    return 0

def report_command(args):
    """Handle report command"""
    print(f"📊 Generating report: {args.output}")
    print(f"📋 Format: {args.format}")
    
    try:
        from strikesuite.core import ReportGenerator
        generator = ReportGenerator()
        
        # Create sample scan data for report generation
        scan_data = [{
            'scan_type': 'network_scan',
            'target': 'example.com',
            'timestamp': '2024-01-01 12:00:00',
            'results': {
                'open_ports': [22, 80, 443],
                'services': ['ssh', 'http', 'https'],
                'vulnerabilities': []
            }
        }]
        
        config = {
            'title': args.title,
            'format': args.format.lower(),
            'output_path': args.output
        }
        
        # Generate report
        generator.generate_report(scan_data, config)
        
        print(f"✅ Report generated: {args.output}")
        
    except Exception as e:
        print(f"❌ Report generation failed: {e}")
        return 1
    
    return 0

def main():
    """Main CLI entry point"""
    setup_cli_logging()
    
    parser = argparse.ArgumentParser(
        description="StrikeSuite CLI - Advanced Cybersecurity Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  strikesuite scan --target 192.168.1.0/24 --type network
  strikesuite scan --target example.com --type ports --ports 80,443,22
  strikesuite test --target https://api.example.com --type api
  strikesuite test --target https://example.com --type vulnerability
  strikesuite report --output report.pdf --format PDF
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Perform network scanning')
    scan_parser.add_argument('--target', required=True, help='Target to scan')
    scan_parser.add_argument('--type', choices=['network', 'ports'], default='network', help='Scan type')
    scan_parser.add_argument('--ports', help='Ports to scan (comma-separated)')
    scan_parser.add_argument('--options', help='Additional scan options')
    scan_parser.set_defaults(func=scan_command)
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Perform security testing')
    test_parser.add_argument('--target', required=True, help='Target to test')
    test_parser.add_argument('--type', choices=['api', 'vulnerability'], required=True, help='Test type')
    test_parser.set_defaults(func=test_command)
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate security reports')
    report_parser.add_argument('--output', required=True, help='Output file path')
    report_parser.add_argument('--format', choices=['PDF', 'HTML', 'JSON'], default='PDF', help='Report format')
    report_parser.add_argument('--title', default='Security Assessment Report', help='Report title')
    report_parser.set_defaults(func=report_command)
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Execute command
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n⚠️ Operation cancelled by user")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())

