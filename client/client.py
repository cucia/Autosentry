#!/usr/bin/env python3
"""
AutoSentry Client (Fixed Version)
Command-line client for the AutoSentry VAPT tool
"""

import requests
import json
import time
import argparse
import sys
from typing import Dict, Any, Optional

class AutoSentryClient:
    """Client for AutoSentry VAPT tool"""

    def __init__(self, server_url: str = "http://localhost:5000", api_key: str = ""):
        """Initialize client"""
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()

        # Set API key header if provided
        if self.api_key:
            self.session.headers.update({'X-API-Key': self.api_key})

    def health_check(self) -> Dict[str, Any]:
        """Check if server is healthy"""
        try:
            response = self.session.get(f"{self.server_url}/health", timeout=10)
            response.raise_for_status()
            return {'status': 'healthy', 'response': response.json()}
        except requests.exceptions.RequestException as e:
            return {'status': 'error', 'error': str(e)}

    def start_scan(self, target_url: str, scan_type: str = "basic") -> Dict[str, Any]:
        """Start a vulnerability scan"""
        data = {
            'url': target_url,
            'scan_type': scan_type
        }

        try:
            print(f"🔍 Starting {scan_type} scan for {target_url}...")
            print("⏳ This may take a few minutes depending on the scan type...")

            response = self.session.post(
                f"{self.server_url}/api/scan",
                json=data,
                timeout=600  # 10 minutes timeout for scans
            )
            response.raise_for_status()
            result = response.json()

            if result.get('success'):
                print("✅ Scan completed successfully!")
                print(f"📊 Scan ID: {result.get('scan_id')}")
                return result
            else:
                print(f"❌ Scan failed: {result.get('error')}")
                return result

        except requests.exceptions.RequestException as e:
            error_result = {'success': False, 'error': str(e)}
            print(f"❌ Request failed: {str(e)}")
            return error_result

    def get_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan results by ID"""
        try:
            response = self.session.get(f"{self.server_url}/api/results/{scan_id}")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"❌ Failed to get results: {str(e)}")
            return None

    def get_scanner_status(self) -> Optional[Dict[str, Any]]:
        """Get status of all scanners"""
        try:
            response = self.session.get(f"{self.server_url}/api/scanner-status")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"❌ Failed to get scanner status: {str(e)}")
            return None

    def display_summary(self, results: Dict[str, Any]):
        """Display scan results summary"""
        print("\n" + "="*80)
        print("🛡️  AUTOSENTRY VULNERABILITY SCAN SUMMARY")
        print("="*80)

        # Get the results data
        if 'results' in results:
            scan_data = results['results']
        else:
            scan_data = results

        print(f"🎯 Target: {scan_data.get('target_url', results.get('url', 'N/A'))}")
        print(f"🔍 Scan Type: {scan_data.get('scan_type', 'N/A')}")
        print(f"⏰ Timestamp: {scan_data.get('timestamp', 'N/A')}")

        # Summary statistics
        if 'summary' in scan_data:
            summary = scan_data['summary']
            print(f"\n📊 VULNERABILITIES FOUND:")
            print(f"   📈 Total: {summary.get('total_vulnerabilities', 0)}")
            print(f"   🔴 High Risk: {summary.get('high_risk', 0)}")
            print(f"   🟡 Medium Risk: {summary.get('medium_risk', 0)}")
            print(f"   🟢 Low Risk: {summary.get('low_risk', 0)}")
            print(f"   ℹ️  Info: {summary.get('info', 0)}")

        # Scanner breakdown
        if 'scanner_results' in scan_data:
            print(f"\n🔍 SCANNER RESULTS:")
            scanner_results = scan_data['scanner_results']

            for scanner_name, scanner_data in scanner_results.items():
                icon = "🔍" if scanner_name == "basic" else "🌐" if scanner_name == "nmap" else "🔎"
                if 'error' in scanner_data:
                    print(f"   {icon} {scanner_name.upper()}: ❌ ERROR - {scanner_data['error']}")
                else:
                    vuln_count = len(scanner_data.get('vulnerabilities', []))
                    print(f"   {icon} {scanner_name.upper()}: ✅ {vuln_count} findings")

        print("="*80)

    def display_detailed_results(self, results: Dict[str, Any]):
        """Display detailed scan results"""
        self.display_summary(results)

        # Get the results data
        if 'results' in results:
            scan_data = results['results']
        else:
            scan_data = results

        if 'scanner_results' not in scan_data:
            print("\n❌ No detailed results available.")
            return

        scanner_results = scan_data['scanner_results']

        for scanner_name, scanner_data in scanner_results.items():
            print(f"\n{'-'*60}")
            print(f"🔍 {scanner_name.upper()} DETAILED RESULTS")
            print(f"{'-'*60}")

            if 'error' in scanner_data:
                print(f"❌ Error: {scanner_data['error']}")
                continue

            vulnerabilities = scanner_data.get('vulnerabilities', [])

            if not vulnerabilities:
                print("✅ No vulnerabilities found by this scanner.")
                continue

            # Group by risk level
            risk_groups = {'high': [], 'medium': [], 'low': [], 'info': []}
            for vuln in vulnerabilities:
                risk = vuln.get('risk_level', 'info').lower()
                if risk in ['critical', 'high']:
                    risk_groups['high'].append(vuln)
                elif risk == 'medium':
                    risk_groups['medium'].append(vuln)
                elif risk == 'low':
                    risk_groups['low'].append(vuln)
                else:
                    risk_groups['info'].append(vuln)

            # Display by risk level
            for risk_level, vulns in risk_groups.items():
                if vulns:
                    risk_icon = "🔴" if risk_level == "high" else "🟡" if risk_level == "medium" else "🟢" if risk_level == "low" else "ℹ️"
                    print(f"\n{risk_icon} {risk_level.upper()} RISK ({len(vulns)} findings):")

                    for i, vuln in enumerate(vulns, 1):
                        print(f"\n   {i}. {vuln.get('name', 'Unknown Vulnerability')}")
                        print(f"      🎯 URL: {vuln.get('url', 'N/A')}")
                        print(f"      📝 Description: {vuln.get('description', 'N/A')}")

                        if vuln.get('evidence'):
                            evidence = str(vuln.get('evidence'))[:100]
                            print(f"      🔍 Evidence: {evidence}{'...' if len(str(vuln.get('evidence', ''))) > 100 else ''}")

                        if vuln.get('solution'):
                            print(f"      💡 Solution: {vuln.get('solution')}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="AutoSentry VAPT Tool Client")
    parser.add_argument('--server', '-s', 
                       default='http://localhost:5000',
                       help='AutoSentry server URL (default: http://localhost:5000)')
    parser.add_argument('--api-key', '-k',
                       default='',
                       help='API key for authentication')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Health check command
    health_parser = subparsers.add_parser('health', help='Check server health')

    # Scanner status command
    status_parser = subparsers.add_parser('status', help='Check scanner status')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Start a vulnerability scan')
    scan_parser.add_argument('url', help='Target URL to scan')
    scan_parser.add_argument('--type', '-t',
                           choices=['basic', 'nmap', 'nikto', 'full'],
                           default='basic',
                           help='Type of scan to perform (default: basic)')
    scan_parser.add_argument('--detailed', '-d',
                           action='store_true',
                           help='Show detailed results')

    # Results command
    results_parser = subparsers.add_parser('results', help='Get scan results')
    results_parser.add_argument('scan_id', help='Scan ID to retrieve')
    results_parser.add_argument('--detailed', '-d',
                               action='store_true',
                               help='Show detailed results')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        print("\n🛡️  AutoSentry VAPT Tool Client")
        print("Examples:")
        print("  python main.py client health")
        print("  python main.py client status")  
        print("  python main.py client scan https://example.com --type basic")
        print("  python main.py client scan https://example.com --type full --detailed")
        sys.exit(1)

    # Initialize client
    client = AutoSentryClient(args.server, args.api_key)

    # Execute command
    if args.command == 'health':
        result = client.health_check()
        if result['status'] == 'healthy':
            print("✅ Server is healthy")
            print(f"📊 Response: {json.dumps(result['response'], indent=2)}")
        else:
            print("❌ Server is not healthy")
            print(f"❌ Error: {result['error']}")
            sys.exit(1)

    elif args.command == 'status':
        status = client.get_scanner_status()
        if status:
            print("🔍 Scanner Status:")
            print("=" * 30)
            scanners = status.get('scanners', {})
            for scanner, info in scanners.items():
                available = info.get('available', False)
                version = info.get('version', 'Unknown')
                status_icon = "✅" if available else "❌"
                print(f"{status_icon} {scanner.upper()}: {version}")

            print(f"\n⏰ Last checked: {status.get('timestamp', 'Unknown')}")
        else:
            print("❌ Failed to get scanner status")
            sys.exit(1)

    elif args.command == 'scan':
        result = client.start_scan(args.url, args.type)

        if result.get('success'):
            scan_id = result.get('scan_id')

            if args.detailed:
                client.display_detailed_results(result)
            else:
                client.display_summary(result)

            print(f"\n💾 Scan saved with ID: {scan_id}")
            print(f"📄 To view again: python main.py client results {scan_id}")

        else:
            print(f"❌ Scan failed: {result.get('error')}")
            sys.exit(1)

    elif args.command == 'results':
        results = client.get_results(args.scan_id)

        if results:
            if args.detailed:
                client.display_detailed_results(results)
            else:
                client.display_summary(results)
        else:
            print(f"❌ Failed to retrieve results for scan ID: {args.scan_id}")
            sys.exit(1)

if __name__ == '__main__':
    main()
