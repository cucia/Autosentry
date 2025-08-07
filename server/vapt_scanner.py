#!/usr/bin/env python3
"""
AutoSentry VAPT Scanner (Fixed Version)
Main scanner orchestrator that coordinates different vulnerability scanners
"""

import logging
import json
import csv
import io
from datetime import datetime
from urllib.parse import urlparse
import concurrent.futures
import threading
import subprocess
import requests

logger = logging.getLogger(__name__)

class VAPTScanner:
    """Main VAPT Scanner class that orchestrates different vulnerability scanners"""

    def __init__(self):
        """Initialize all scanners"""
        self.scanners = {
            'basic': self._basic_web_scan,
            'nmap': self._nmap_scan,
            'nikto': self._nikto_scan
        }

        # Lock for thread-safe operations
        self._lock = threading.Lock()

        logger.info("VAPTScanner initialized with Basic, Nmap, and Nikto scanners")

    def scan(self, target_url: str, scan_type: str = 'full') -> dict:
        """Perform vulnerability scan on target URL"""
        try:
            # Sanitize and validate URL
            if not self._validate_url(target_url):
                raise ValueError("Invalid target URL")

            logger.info(f"Starting {scan_type} scan for {target_url}")

            results = {
                'target_url': target_url,
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

            # Determine which scanners to run
            scanners_to_run = []
            if scan_type == 'full':
                scanners_to_run = ['basic', 'nmap', 'nikto']
            elif scan_type in self.scanners:
                scanners_to_run = [scan_type]
            else:
                scanners_to_run = ['basic']  # Default fallback

            # Run scanners
            for scanner_name in scanners_to_run:
                try:
                    scanner_result = self.scanners[scanner_name](target_url)
                    results['scanner_results'][scanner_name] = scanner_result
                except Exception as e:
                    logger.error(f"Scanner {scanner_name} failed: {str(e)}")
                    results['scanner_results'][scanner_name] = {
                        'error': str(e),
                        'vulnerabilities': [],
                        'scan_info': {}
                    }

            # Calculate summary statistics
            results['summary'] = self._calculate_summary(results['scanner_results'])

            logger.info(f"Scan completed for {target_url} - Found {results['summary']['total_vulnerabilities']} vulnerabilities")

            return results

        except Exception as e:
            logger.error(f"Scan failed for {target_url}: {str(e)}")
            raise

    def _validate_url(self, url: str) -> bool:
        """Validate URL format"""
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False

    def _basic_web_scan(self, target_url: str) -> dict:
        """Perform basic web vulnerability scan"""
        vulnerabilities = []

        try:
            # Disable SSL warnings for testing
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            response = requests.get(target_url, timeout=10, verify=False)

            # Check for missing security headers
            security_headers = {
                'X-Frame-Options': 'Protects against clickjacking attacks',
                'X-Content-Type-Options': 'Prevents MIME type sniffing',
                'X-XSS-Protection': 'Enables XSS filtering',
                'Strict-Transport-Security': 'Enforces secure HTTPS connections',
                'Content-Security-Policy': 'Prevents code injection attacks'
            }

            for header, description in security_headers.items():
                if header not in response.headers:
                    risk_level = 'medium' if header in ['X-Frame-Options', 'Content-Security-Policy'] else 'low'
                    vulnerabilities.append({
                        'name': f'Missing Security Header: {header}',
                        'description': f'Missing {header} header. {description}.',
                        'risk_level': risk_level,
                        'url': target_url,
                        'evidence': f'HTTP response missing {header} header',
                        'solution': f'Add {header} header to web server configuration',
                        'scanner': 'Basic Web Scanner'
                    })

            # Check for server information disclosure
            if 'Server' in response.headers:
                vulnerabilities.append({
                    'name': 'Server Information Disclosure',
                    'description': f'Server software and version disclosed: {response.headers["Server"]}',
                    'risk_level': 'info',
                    'url': target_url,
                    'evidence': f'Server: {response.headers["Server"]}',
                    'solution': 'Configure web server to hide version information',
                    'scanner': 'Basic Web Scanner'
                })

            # Check for insecure cookies
            for cookie in response.cookies:
                issues = []
                if not cookie.secure:
                    issues.append('not marked as Secure')
                if not getattr(cookie, 'has_nonstandard_attr', lambda x: False)('HttpOnly'):
                    issues.append('not marked as HttpOnly')

                if issues:
                    vulnerabilities.append({
                        'name': f'Insecure Cookie: {cookie.name}',
                        'description': f'Cookie {cookie.name} is {" and ".join(issues)}',
                        'risk_level': 'low',
                        'url': target_url,
                        'evidence': f'Cookie: {cookie.name}={cookie.value}',
                        'solution': 'Set Secure and HttpOnly flags on cookies',
                        'scanner': 'Basic Web Scanner'
                    })

            return {
                'vulnerabilities': vulnerabilities,
                'scan_info': {
                    'status_code': response.status_code,
                    'response_headers': dict(response.headers),
                    'cookies_count': len(response.cookies),
                    'response_size': len(response.content),
                    'scanner': 'Basic Web Scanner'
                }
            }

        except Exception as e:
            return {
                'error': f'Basic web scan failed: {str(e)}',
                'vulnerabilities': [],
                'scan_info': {'scanner': 'Basic Web Scanner'}
            }

    def _nmap_scan(self, target_url: str) -> dict:
        """Perform Nmap network scan"""
        vulnerabilities = []

        try:
            # Extract hostname from URL
            parsed_url = urlparse(target_url)
            hostname = parsed_url.hostname

            if not hostname:
                return {
                    'error': 'Could not extract hostname from URL',
                    'vulnerabilities': [],
                    'scan_info': {'scanner': 'Nmap'}
                }

            # Run Nmap scan
            cmd = ['nmap', '-T4', '-F', '--version-detection', hostname]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode == 0:
                # Parse Nmap output
                lines = result.stdout.split('\n')
                ports_found = []

                for line in lines:
                    if '/tcp' in line and 'open' in line:
                        port_info = line.strip()
                        ports_found.append(port_info)

                        # Analyze port for potential risks
                        if '21/tcp' in line and 'ftp' in line.lower():
                            vulnerabilities.append({
                                'name': 'FTP Service Detected',
                                'description': 'FTP service detected. FTP transmits credentials in plain text.',
                                'risk_level': 'medium',
                                'url': f'ftp://{hostname}:21',
                                'evidence': port_info,
                                'solution': 'Consider using SFTP instead of FTP',
                                'scanner': 'Nmap'
                            })
                        elif '23/tcp' in line and 'telnet' in line.lower():
                            vulnerabilities.append({
                                'name': 'Telnet Service Detected',
                                'description': 'Telnet service detected. Telnet transmits data in plain text.',
                                'risk_level': 'high',
                                'url': f'telnet://{hostname}:23',
                                'evidence': port_info,
                                'solution': 'Replace Telnet with SSH',
                                'scanner': 'Nmap'
                            })
                        else:
                            vulnerabilities.append({
                                'name': 'Open Port Detected',
                                'description': f'Open network service: {port_info}',
                                'risk_level': 'info',
                                'url': f'tcp://{hostname}',
                                'evidence': port_info,
                                'solution': 'Ensure this service needs to be publicly accessible',
                                'scanner': 'Nmap'
                            })

                return {
                    'vulnerabilities': vulnerabilities,
                    'scan_info': {
                        'target_host': hostname,
                        'ports_scanned': 'Fast scan (most common ports)',
                        'ports_found': len(ports_found),
                        'scan_output': result.stdout,
                        'scanner': 'Nmap'
                    }
                }
            else:
                return {
                    'error': f'Nmap scan failed: {result.stderr}',
                    'vulnerabilities': [],
                    'scan_info': {'scanner': 'Nmap'}
                }

        except subprocess.TimeoutExpired:
            return {
                'error': 'Nmap scan timed out',
                'vulnerabilities': [],
                'scan_info': {'scanner': 'Nmap'}
            }
        except FileNotFoundError:
            return {
                'error': 'Nmap not installed or not found in PATH',
                'vulnerabilities': [],
                'scan_info': {'scanner': 'Nmap'}
            }
        except Exception as e:
            return {
                'error': f'Nmap scan error: {str(e)}',
                'vulnerabilities': [],
                'scan_info': {'scanner': 'Nmap'}
            }

    def _nikto_scan(self, target_url: str) -> dict:
        """Perform Nikto web vulnerability scan"""
        vulnerabilities = []

        try:
            # Run Nikto scan
            cmd = ['nikto', '-h', target_url, '-Format', 'txt', '-timeout', '5']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

            # Nikto returns different exit codes, 0 or 2 can both indicate success
            if result.returncode in [0, 2]:
                # Parse Nikto output
                lines = result.stdout.split('\n')
                findings = []

                for line in lines:
                    line = line.strip()
                    if line.startswith('+ ') and ':' in line:
                        finding = line[2:]  # Remove '+ ' prefix
                        findings.append(finding)

                        # Categorize findings
                        risk_level = 'low'  # Default
                        if any(keyword in finding.lower() for keyword in ['sql', 'xss', 'injection', 'script']):
                            risk_level = 'high'
                        elif any(keyword in finding.lower() for keyword in ['admin', 'backup', 'config', 'password']):
                            risk_level = 'medium'

                        vulnerabilities.append({
                            'name': 'Web Server Vulnerability',
                            'description': finding,
                            'risk_level': risk_level,
                            'url': target_url,
                            'evidence': finding,
                            'solution': 'Review and remediate the identified issue',
                            'scanner': 'Nikto'
                        })

                return {
                    'vulnerabilities': vulnerabilities,
                    'scan_info': {
                        'findings_count': len(findings),
                        'scan_output': result.stdout[:1000],  # Truncate for readability
                        'scanner': 'Nikto'
                    }
                }
            else:
                return {
                    'error': f'Nikto scan failed: {result.stderr}',
                    'vulnerabilities': [],
                    'scan_info': {'scanner': 'Nikto'}
                }

        except subprocess.TimeoutExpired:
            return {
                'error': 'Nikto scan timed out',
                'vulnerabilities': [],
                'scan_info': {'scanner': 'Nikto'}
            }
        except FileNotFoundError:
            return {
                'error': 'Nikto not installed or not found in PATH',
                'vulnerabilities': [],
                'scan_info': {'scanner': 'Nikto'}
            }
        except Exception as e:
            return {
                'error': f'Nikto scan error: {str(e)}',
                'vulnerabilities': [],
                'scan_info': {'scanner': 'Nikto'}
            }

    def _calculate_summary(self, scanner_results: dict) -> dict:
        """Calculate summary statistics from all scanner results"""
        summary = {
            'total_vulnerabilities': 0,
            'high_risk': 0,
            'medium_risk': 0,
            'low_risk': 0,
            'info': 0,
            'by_scanner': {}
        }

        for scanner_name, results in scanner_results.items():
            if 'error' in results:
                continue

            vulnerabilities = results.get('vulnerabilities', [])
            scanner_summary = {
                'total': len(vulnerabilities),
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }

            for vuln in vulnerabilities:
                risk_level = vuln.get('risk_level', 'info').lower()

                if risk_level in ['high', 'critical']:
                    scanner_summary['high'] += 1
                elif risk_level == 'medium':
                    scanner_summary['medium'] += 1
                elif risk_level == 'low':
                    scanner_summary['low'] += 1
                else:
                    scanner_summary['info'] += 1

            summary['by_scanner'][scanner_name] = scanner_summary
            summary['total_vulnerabilities'] += scanner_summary['total']
            summary['high_risk'] += scanner_summary['high']
            summary['medium_risk'] += scanner_summary['medium']
            summary['low_risk'] += scanner_summary['low']
            summary['info'] += scanner_summary['info']

        return summary

    def export_to_csv(self, scan_results: dict) -> str:
        """Export scan results to CSV format"""
        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow([
            'Scanner', 'Vulnerability', 'Risk Level', 'Description', 
            'URL', 'Evidence', 'Solution'
        ])

        # Write vulnerability data
        results = scan_results.get('results', {})
        scanner_results = results.get('scanner_results', {})

        for scanner_name, scanner_data in scanner_results.items():
            if 'error' in scanner_data:
                writer.writerow([scanner_name.upper(), 'ERROR', 'N/A', scanner_data['error'], '', '', ''])
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
                    vuln.get('solution', '')
                ])

        # Write summary
        writer.writerow([])
        writer.writerow(['SCAN SUMMARY'])
        summary = results.get('summary', {})
        writer.writerow(['Total Vulnerabilities', summary.get('total_vulnerabilities', 0)])
        writer.writerow(['High Risk', summary.get('high_risk', 0)])
        writer.writerow(['Medium Risk', summary.get('medium_risk', 0)])
        writer.writerow(['Low Risk', summary.get('low_risk', 0)])
        writer.writerow(['Info', summary.get('info', 0)])

        return output.getvalue()

    def get_scanner_status(self) -> dict:
        """Get status of all scanners"""
        status = {}

        # Check if tools are available
        tools = {
            'nmap': ['nmap', '--version'],
            'nikto': ['nikto', '-Version'],
            'curl': ['curl', '--version']
        }

        for tool_name, cmd in tools.items():
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                status[tool_name] = {
                    'available': result.returncode == 0,
                    'version': result.stdout.split('\n')[0] if result.returncode == 0 else 'Unknown'
                }
            except:
                status[tool_name] = {
                    'available': False,
                    'error': 'Not installed or not accessible'
                }

        return status

    def health_check(self) -> dict:
        """Perform health check on all scanners"""
        health = {
            'overall_status': 'healthy',
            'scanners': {},
            'timestamp': datetime.now().isoformat()
        }

        scanner_status = self.get_scanner_status()

        for scanner_name, status in scanner_status.items():
            if status.get('available', False):
                health['scanners'][scanner_name] = {'status': 'healthy', 'version': status.get('version', 'Unknown')}
            else:
                health['scanners'][scanner_name] = {'status': 'unavailable', 'error': status.get('error', 'Unknown error')}
                # Don't mark overall as unhealthy if some scanners are missing - basic scanning still works

        return health
