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
            results = scanner.scan_network(args.target)
            print(f"✅ Found {len(results)} hosts")
            for host in results:
                print(f"   📍 {host}")
        elif args.type == "ports":
            results = scanner.scan_ports(args.target, args.ports)
            print(f"✅ Found {len(results)} open ports")
            for port in results:
                print(f"   🔌 Port {port['port']}: {port['service']}")
        
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
            results = tester.test_api_security()
            print(f"✅ API test completed: {len(results)} issues found")
        elif args.type == "vulnerability":
            from strikesuite.core import VulnerabilityScanner
            scanner = VulnerabilityScanner()
            results = scanner.scan_vulnerabilities(args.target)
            print(f"✅ Vulnerability scan completed: {len(results)} issues found")
        
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
        
        # Generate report
        generator.generate_report(
            title=args.title,
            format_type=args.format,
            output_path=args.output
        )
        
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

