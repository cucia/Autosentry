#!/usr/bin/env python3
"""
AutoSentry Scanner Function (Fixed Version)
Main scanning function that can be easily integrated into other projects

This is the core scanning function you requested that takes a URL 
and returns vulnerability scan results in various formats.
"""

import json
import logging
import sys
import os
from typing import Dict, List, Union, Optional
from datetime import datetime

# Add server modules to path
current_dir = os.path.dirname(os.path.abspath(__file__))
server_dir = os.path.join(current_dir, 'server')
sys.path.insert(0, server_dir)

try:
    from vapt_scanner import VAPTScanner
    from utils import validate_url, sanitize_url
except ImportError:
    # Fallback imports
    from server.vapt_scanner import VAPTScanner
    from server.utils import validate_url, sanitize_url

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def scan_url(url: str, 
             scan_type: str = 'basic',
             return_format: str = 'json') -> Union[Dict, str, List]:
    """
    Main scanning function - scan a URL for vulnerabilities

    Args:
        url (str): Target URL to scan (e.g., 'https://example.com')
        scan_type (str): Type of scan to perform:
            - 'basic': Basic web security checks (default)
            - 'nmap': Network/port scanning  
            - 'nikto': Web vulnerability scanning
            - 'full': All scanners combined
        return_format (str): Format for results:
            - 'json': Return as dictionary (default)
            - 'csv': Return as CSV string
            - 'list': Return as list of vulnerability dictionaries

    Returns:
        Union[Dict, str, List]: Scan results in specified format

    Examples:
        >>> # Basic scan returning JSON
        >>> results = scan_url('https://example.com')
        >>> print(f"Found {results['summary']['total_vulnerabilities']} vulnerabilities")

        >>> # Full scan with CSV output
        >>> csv_results = scan_url('https://example.com', 'full', 'csv')
        >>> with open('results.csv', 'w') as f:
        ...     f.write(csv_results)

        >>> # Get just the vulnerability list
        >>> vulns = scan_url('https://example.com', 'basic', 'list')
        >>> for vuln in vulns:
        ...     print(f"{vuln['name']} - {vuln['risk_level']}")
    """

    try:
        # Validate and sanitize URL
        if not url or not isinstance(url, str):
            raise ValueError("URL must be a non-empty string")

        if not validate_url(url):
            # Try to sanitize the URL
            url = sanitize_url(url)
            if not url:
                raise ValueError(f"Invalid URL format: {url}")

        # Initialize scanner
        logger.info(f"Initializing VAPT scanner for {scan_type} scan")
        scanner = VAPTScanner()

        # Perform scan
        logger.info(f"Starting {scan_type} scan for {url}")
        results = scanner.scan(url, scan_type)

        # Return results in requested format
        if return_format.lower() == 'json':
            return results

        elif return_format.lower() == 'csv':
            return convert_to_csv(results)

        elif return_format.lower() == 'list':
            return extract_vulnerabilities_list(results)

        else:
            raise ValueError(f"Unsupported return format: {return_format}")

    except Exception as e:
        logger.error(f"Scan failed for {url}: {str(e)}")

        # Return error in requested format
        error_result = {
            'error': str(e),
            'target_url': url,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'scanner_results': {},
            'summary': {
                'total_vulnerabilities': 0,
                'high_risk': 0,
                'medium_risk': 0,
                'low_risk': 0,
                'info': 0
            }
        }

        if return_format.lower() == 'json':
            return error_result
        elif return_format.lower() == 'csv':
            return f"Error,{str(e)},,,,,\n"
        else:  # list
            return []

def convert_to_csv(results: Dict) -> str:
    """Convert scan results to CSV format"""
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow([
        'Scanner', 'Vulnerability', 'Risk Level', 'Description',
        'URL', 'Evidence', 'Solution', 'Timestamp'
    ])

    # Write scan metadata
    writer.writerow([
        'SCAN_INFO', 'Target URL', 'N/A', results.get('target_url', ''),
        '', '', '', results.get('timestamp', '')
    ])

    writer.writerow([
        'SCAN_INFO', 'Scan Type', 'N/A', results.get('scan_type', ''),
        '', '', '', ''
    ])

    # Write vulnerabilities
    scanner_results = results.get('scanner_results', {})

    for scanner_name, scanner_data in scanner_results.items():
        if 'error' in scanner_data:
            writer.writerow([
                scanner_name.upper(), 'SCANNER_ERROR', 'N/A', 
                scanner_data['error'], '', '', '', ''
            ])
            continue

        vulnerabilities = scanner_data.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            writer.writerow([
                scanner_name.upper(),
                vuln.get('name', ''),
                vuln.get('risk_level', ''),
                vuln.get('description', ''),
                vuln.get('url', ''),
                vuln.get('evidence', ''),
                vuln.get('solution', ''),
                results.get('timestamp', '')
            ])

    # Write summary section
    writer.writerow([])
    writer.writerow(['SUMMARY', 'Metric', 'Count', '', '', '', '', ''])

    summary = results.get('summary', {})
    summary_items = [
        ('Total Vulnerabilities', summary.get('total_vulnerabilities', 0)),
        ('High Risk', summary.get('high_risk', 0)),
        ('Medium Risk', summary.get('medium_risk', 0)),
        ('Low Risk', summary.get('low_risk', 0)),
        ('Info', summary.get('info', 0))
    ]

    for item_name, count in summary_items:
        writer.writerow(['SUMMARY', item_name, str(count), '', '', '', '', ''])

    return output.getvalue()

def extract_vulnerabilities_list(results: Dict) -> List[Dict]:
    """Extract all vulnerabilities as a flat list"""
    vulnerabilities = []

    scanner_results = results.get('scanner_results', {})

    for scanner_name, scanner_data in scanner_results.items():
        if 'error' in scanner_data:
            # Add error as a "vulnerability"
            vulnerabilities.append({
                'name': f'{scanner_name.upper()} Scanner Error',
                'description': scanner_data['error'],
                'risk_level': 'info',
                'url': results.get('target_url', ''),
                'evidence': scanner_data['error'],
                'solution': f'Fix {scanner_name} scanner configuration',
                'scanner': scanner_name
            })
            continue

        vulns = scanner_data.get('vulnerabilities', [])
        for vuln in vulns:
            # Ensure scanner name is included
            vuln['scanner'] = scanner_name
            vulnerabilities.append(vuln)

    return vulnerabilities

def batch_scan_urls(urls: List[str], 
                   scan_type: str = 'basic',
                   return_format: str = 'json') -> Dict[str, Union[Dict, str, List]]:
    """
    Scan multiple URLs and return combined results

    Args:
        urls (List[str]): List of URLs to scan
        scan_type (str): Type of scan to perform
        return_format (str): Format for results

    Returns:
        Dict: Results keyed by URL

    Example:
        >>> urls = ['https://example1.com', 'https://example2.com']
        >>> results = batch_scan_urls(urls, 'basic', 'json')
        >>> for url, result in results.items():
        ...     vulns = result.get('summary', {}).get('total_vulnerabilities', 0)
        ...     print(f"{url}: {vulns} vulnerabilities")
    """
    results = {}

    for i, url in enumerate(urls, 1):
        logger.info(f"Scanning {i}/{len(urls)}: {url}")
        try:
            result = scan_url(url, scan_type, return_format)
            results[url] = result
        except Exception as e:
            logger.error(f"Failed to scan {url}: {str(e)}")
            if return_format.lower() == 'json':
                results[url] = {
                    'error': str(e),
                    'target_url': url,
                    'scan_type': scan_type,
                    'timestamp': datetime.now().isoformat()
                }
            else:
                results[url] = f"Error: {str(e)}"

    return results

def get_scanner_health() -> Dict[str, Dict]:
    """
    Check health status of all scanners

    Returns:
        Dict: Health status of each scanner

    Example:
        >>> health = get_scanner_health()
        >>> for scanner, status in health['scanners'].items():
        ...     print(f"{scanner}: {status['status']}")
    """
    try:
        scanner = VAPTScanner()
        return scanner.health_check()
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {
            'overall_status': 'error',
            'error': str(e),
            'scanners': {
                'basic': {'status': 'unknown'},
                'nmap': {'status': 'unknown'},
                'nikto': {'status': 'unknown'}
            },
            'timestamp': datetime.now().isoformat()
        }

# Example usage and CLI interface
if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="AutoSentry URL Scanner Function")
    parser.add_argument('url', help='URL to scan')
    parser.add_argument('--type', '-t', default='basic',
                       choices=['basic', 'nmap', 'nikto', 'full'],
                       help='Scan type (default: basic)')
    parser.add_argument('--format', '-f', default='json',
                       choices=['json', 'csv', 'list'],
                       help='Output format (default: json)')
    parser.add_argument('--output', '-o', help='Output file (optional)')
    parser.add_argument('--health', action='store_true',
                       help='Check scanner health')
    parser.add_argument('--batch', help='Scan multiple URLs from file (one per line)')

    args = parser.parse_args()

    # Setup logging for CLI
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    try:
        if args.health:
            health = get_scanner_health()
            print("🔍 Scanner Health Status:")
            print("=" * 30)
            for scanner, status in health.get('scanners', {}).items():
                status_icon = "✅" if status.get('status') == 'healthy' else "❌"
                print(f"{status_icon} {scanner.upper()}: {status.get('status', 'unknown')}")
            sys.exit(0)

        if args.batch:
            # Batch scanning
            print(f"📂 Reading URLs from {args.batch}...")
            with open(args.batch, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]

            print(f"🔍 Starting batch scan of {len(urls)} URLs...")
            results = batch_scan_urls(urls, args.type, args.format)

            if args.output:
                with open(args.output, 'w') as f:
                    if args.format == 'json':
                        json.dump(results, f, indent=2)
                    else:
                        f.write(str(results))
                print(f"📄 Results saved to {args.output}")
            else:
                if args.format == 'json':
                    print(json.dumps(results, indent=2))
                else:
                    print(results)

        else:
            # Single URL scan
            print(f"🔍 Scanning {args.url} with {args.type} scanner(s)...")

            result = scan_url(args.url, args.type, args.format)

            if args.output:
                # Write to file
                with open(args.output, 'w') as f:
                    if args.format == 'json':
                        json.dump(result, f, indent=2)
                    else:
                        f.write(str(result))
                print(f"📄 Results saved to {args.output}")
            else:
                # Print to console
                if args.format == 'json':
                    print(json.dumps(result, indent=2))
                else:
                    print(result)

    except KeyboardInterrupt:
        print("\n⏹️  Scan cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
