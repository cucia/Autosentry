#!/usr/bin/env python3
"""
AutoSentry VAPT Scanner (Fixed Version with Working Nmap/Nikto)
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
import time
import re

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

        # Check which scanners are available
        self.available_scanners = self._check_available_scanners()

        logger.info(f"VAPTScanner initialized with {', '.join(self.available_scanners)} scanners")

    def _check_available_scanners(self) -> list:
        """Check which external scanners are available"""
        available = ['basic']  # Basic scanner always available

        # Check Nmap
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                available.append('nmap')
                logger.info("Nmap scanner available")
        except:
            logger.warning("Nmap scanner not available")

        # Check Nikto
        try:
            result = subprocess.run(['nikto', '-Version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode in [0, 2]:  # Nikto can return 2 and still be working
                available.append('nikto')
                logger.info("Nikto scanner available")
        except:
            logger.warning("Nikto scanner not available")

        return available

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

            # Determine which scanners to run based on availability
            scanners_to_run = []
            if scan_type == 'full':
                scanners_to_run = self.available_scanners
            elif scan_type in self.available_scanners:
                scanners_to_run = [scan_type]
            else:
                logger.warning(f"Scanner {scan_type} not available, using basic scan")
                scanners_to_run = ['basic']

            logger.info(f"Running scanners: {scanners_to_run}")

            # Run scanners sequentially to avoid resource conflicts
            for scanner_name in scanners_to_run:
                try:
                    logger.info(f"Running {scanner_name} scanner...")
                    scanner_result = self.scanners[scanner_name](target_url)
                    results['scanner_results'][scanner_name] = scanner_result
                    logger.info(f"{scanner_name} scanner completed")
                except Exception as e:
                    logger.error(f"Scanner {scanner_name} failed: {str(e)}")
                    results['scanner_results'][scanner_name] = {
                        'error': str(e),
                        'vulnerabilities': [],
                        'scan_info': {'scanner': scanner_name}
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
        scan_info = {'scanner': 'Basic Web Scanner', 'start_time': time.time()}

        try:
            # Disable SSL warnings for testing
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            logger.info(f"Basic web scan: Connecting to {target_url}")
            response = requests.get(target_url, timeout=15, verify=False, 
                                  headers={'User-Agent': 'AutoSentry-Scanner/1.0'})

            scan_info.update({
                'status_code': response.status_code,
                'response_time': time.time() - scan_info['start_time'],
                'response_size': len(response.content)
            })

            # Check for missing security headers
            security_headers = {
                'X-Frame-Options': {'risk': 'medium', 'desc': 'Protects against clickjacking attacks'},
                'X-Content-Type-Options': {'risk': 'low', 'desc': 'Prevents MIME type sniffing'},
                'X-XSS-Protection': {'risk': 'low', 'desc': 'Enables XSS filtering'},
                'Strict-Transport-Security': {'risk': 'medium', 'desc': 'Enforces secure HTTPS connections'},
                'Content-Security-Policy': {'risk': 'medium', 'desc': 'Prevents code injection attacks'},
                'Referrer-Policy': {'risk': 'low', 'desc': 'Controls referrer information'},
                'Permissions-Policy': {'risk': 'low', 'desc': 'Controls browser features'}
            }

            for header, info in security_headers.items():
                if header not in response.headers:
                    vulnerabilities.append({
                        'name': f'Missing Security Header: {header}',
                        'description': f'Missing {header} header. {info["desc"]}.',
                        'risk_level': info['risk'],
                        'url': target_url,
                        'evidence': f'HTTP response missing {header} header',
                        'solution': f'Add "{header}" header to web server configuration',
                        'scanner': 'Basic Web Scanner'
                    })

            # Check for server information disclosure
            if 'Server' in response.headers:
                server_header = response.headers['Server']
                vulnerabilities.append({
                    'name': 'Server Information Disclosure',
                    'description': f'Server software and version disclosed: {server_header}',
                    'risk_level': 'info',
                    'url': target_url,
                    'evidence': f'Server: {server_header}',
                    'solution': 'Configure web server to hide version information',
                    'scanner': 'Basic Web Scanner'
                })

            # Check X-Powered-By header
            if 'X-Powered-By' in response.headers:
                powered_by = response.headers['X-Powered-By']
                vulnerabilities.append({
                    'name': 'Technology Stack Disclosure',
                    'description': f'Technology stack disclosed: {powered_by}',
                    'risk_level': 'info',
                    'url': target_url,
                    'evidence': f'X-Powered-By: {powered_by}',
                    'solution': 'Remove or modify X-Powered-By header',
                    'scanner': 'Basic Web Scanner'
                })

            # Check for insecure cookies
            for cookie in response.cookies:
                issues = []
                if not cookie.secure and target_url.startswith('https://'):
                    issues.append('not marked as Secure')
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append('not marked as HttpOnly')

                if issues:
                    vulnerabilities.append({
                        'name': f'Insecure Cookie: {cookie.name}',
                        'description': f'Cookie "{cookie.name}" is {" and ".join(issues)}',
                        'risk_level': 'medium' if 'Secure' in issues else 'low',
                        'url': target_url,
                        'evidence': f'Cookie: {cookie.name}={cookie.value[:50]}...',
                        'solution': 'Set Secure and HttpOnly flags on cookies',
                        'scanner': 'Basic Web Scanner'
                    })

            # Check for common HTTP methods
            try:
                methods_response = requests.options(target_url, timeout=10, verify=False)
                if 'Allow' in methods_response.headers:
                    allowed_methods = methods_response.headers['Allow']
                    dangerous_methods = ['TRACE', 'TRACK', 'DELETE', 'PUT']
                    found_dangerous = [method for method in dangerous_methods if method in allowed_methods]

                    if found_dangerous:
                        vulnerabilities.append({
                            'name': 'Dangerous HTTP Methods Allowed',
                            'description': f'Potentially dangerous HTTP methods enabled: {", ".join(found_dangerous)}',
                            'risk_level': 'medium',
                            'url': target_url,
                            'evidence': f'Allow: {allowed_methods}',
                            'solution': 'Disable unnecessary HTTP methods on the web server',
                            'scanner': 'Basic Web Scanner'
                        })
            except:
                pass  # OPTIONS method not supported or other error

            scan_info['vulnerabilities_found'] = len(vulnerabilities)
            scan_info['response_headers'] = dict(response.headers)

            logger.info(f"Basic web scan completed: {len(vulnerabilities)} vulnerabilities found")

            return {
                'vulnerabilities': vulnerabilities,
                'scan_info': scan_info
            }

        except Exception as e:
            logger.error(f"Basic web scan failed: {str(e)}")
            return {
                'error': f'Basic web scan failed: {str(e)}',
                'vulnerabilities': [],
                'scan_info': scan_info
            }

    def _nmap_scan(self, target_url: str) -> dict:
        """Perform Nmap network scan (FIXED VERSION)"""
        vulnerabilities = []
        scan_info = {'scanner': 'Nmap', 'start_time': time.time()}

        try:
            # Extract hostname from URL
            parsed_url = urlparse(target_url)
            hostname = parsed_url.hostname

            if not hostname:
                return {
                    'error': 'Could not extract hostname from URL',
                    'vulnerabilities': [],
                    'scan_info': scan_info
                }

            logger.info(f"Nmap scan: Scanning {hostname}")

            # Run comprehensive Nmap scan
            cmd = [
                'nmap',
                '-T4',                    # Timing template (aggressive)
                '-A',                     # Enable OS detection, version detection, script scanning, and traceroute
                '--top-ports', '1000',    # Scan top 1000 ports
                '-sV',                    # Version detection
                '--script', 'vuln',      # Run vulnerability detection scripts
                hostname
            ]

            logger.info(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

            scan_info['command'] = ' '.join(cmd)
            scan_info['return_code'] = result.returncode
            scan_info['scan_time'] = time.time() - scan_info['start_time']

            if result.returncode == 0:
                output = result.stdout
                scan_info['raw_output'] = output

                # Parse Nmap output for open ports and services
                lines = output.split('\n')
                open_ports = []
                vulnerabilities_found = []

                # Parse open ports
                for line in lines:
                    line = line.strip()
                    if '/tcp' in line and 'open' in line:
                        open_ports.append(line)

                        # Analyze specific ports for security issues
                        port_analysis = self._analyze_port(line, hostname)
                        vulnerabilities.extend(port_analysis)

                    # Look for vulnerability script results
                    elif 'VULNERABLE:' in line:
                        vuln_info = line.split('VULNERABLE:')[1].strip()
                        vulnerabilities_found.append(vuln_info)

                # Parse vulnerability script results
                vuln_section = False
                current_vuln = {}
                for line in lines:
                    if '| ' in line and ('CVE-' in line or 'VULNERABLE' in line):
                        vuln_desc = line.split('| ')[1].strip()
                        vulnerabilities.append({
                            'name': 'Network Vulnerability Detected',
                            'description': vuln_desc,
                            'risk_level': 'high',
                            'url': f'tcp://{hostname}',
                            'evidence': vuln_desc,
                            'solution': 'Update affected service or apply security patches',
                            'scanner': 'Nmap'
                        })

                # Add general port findings
                for port_line in open_ports:
                    vulnerabilities.append({
                        'name': 'Open Network Service',
                        'description': f'Open network service detected: {port_line}',
                        'risk_level': 'info',
                        'url': f'tcp://{hostname}',
                        'evidence': port_line,
                        'solution': 'Ensure this service needs to be publicly accessible and is properly secured',
                        'scanner': 'Nmap'
                    })

                scan_info['open_ports'] = len(open_ports)
                scan_info['ports_found'] = open_ports

                logger.info(f"Nmap scan completed: {len(open_ports)} open ports, {len(vulnerabilities)} findings")

                return {
                    'vulnerabilities': vulnerabilities,
                    'scan_info': scan_info
                }
            else:
                error_msg = result.stderr or 'Nmap scan failed'
                logger.error(f"Nmap scan failed: {error_msg}")
                return {
                    'error': f'Nmap scan failed: {error_msg}',
                    'vulnerabilities': [],
                    'scan_info': scan_info
                }

        except subprocess.TimeoutExpired:
            logger.error("Nmap scan timed out")
            return {
                'error': 'Nmap scan timed out after 3 minutes',
                'vulnerabilities': [],
                'scan_info': scan_info
            }
        except FileNotFoundError:
            logger.error("Nmap not found")
            return {
                'error': 'Nmap not installed or not found in PATH',
                'vulnerabilities': [],
                'scan_info': scan_info
            }
        except Exception as e:
            logger.error(f"Nmap scan error: {str(e)}")
            return {
                'error': f'Nmap scan error: {str(e)}',
                'vulnerabilities': [],
                'scan_info': scan_info
            }

    def _analyze_port(self, port_line: str, hostname: str) -> list:
        """Analyze a specific port for security issues"""
        vulnerabilities = []

        # Extract port number
        port_match = re.search(r'(\d+)/tcp', port_line)
        if not port_match:
            return vulnerabilities

        port = port_match.group(1)

        # Check for specific risky services
        risk_services = {
            '21': {'service': 'FTP', 'risk': 'high', 'reason': 'FTP transmits credentials in plain text'},
            '23': {'service': 'Telnet', 'risk': 'critical', 'reason': 'Telnet transmits all data in plain text'},
            '53': {'service': 'DNS', 'risk': 'medium', 'reason': 'DNS service may be vulnerable to amplification attacks'},
            '135': {'service': 'RPC', 'risk': 'high', 'reason': 'Windows RPC can be exploited'},
            '139': {'service': 'NetBIOS', 'risk': 'medium', 'reason': 'NetBIOS can leak system information'},
            '445': {'service': 'SMB', 'risk': 'high', 'reason': 'SMB is frequently targeted by attackers'},
            '1433': {'service': 'MSSQL', 'risk': 'high', 'reason': 'Database should not be directly accessible'},
            '3306': {'service': 'MySQL', 'risk': 'high', 'reason': 'Database should not be directly accessible'},
            '3389': {'service': 'RDP', 'risk': 'high', 'reason': 'RDP is frequently attacked'},
            '5432': {'service': 'PostgreSQL', 'risk': 'high', 'reason': 'Database should not be directly accessible'},
        }

        if port in risk_services:
            service_info = risk_services[port]
            vulnerabilities.append({
                'name': f'Risky Service: {service_info["service"]}',
                'description': f'{service_info["service"]} service detected on port {port}. {service_info["reason"]}',
                'risk_level': service_info['risk'],
                'url': f'tcp://{hostname}:{port}',
                'evidence': port_line,
                'solution': f'Secure or disable {service_info["service"]} service if not needed',
                'scanner': 'Nmap'
            })

        return vulnerabilities

    def _nikto_scan(self, target_url: str) -> dict:
        """Perform Nikto web vulnerability scan (FIXED VERSION)"""
        vulnerabilities = []
        scan_info = {'scanner': 'Nikto', 'start_time': time.time()}

        try:
            logger.info(f"Nikto scan: Starting scan of {target_url}")

            # Run Nikto scan with reasonable timeout and options
            cmd = [
                'nikto',
                '-h', target_url,
                '-Format', 'txt',
                '-timeout', '10',
                '-maxtime', '5m',  # Maximum 5 minutes
                '-nointeractive'
            ]

            logger.info(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # 5 minutes

            scan_info['command'] = ' '.join(cmd)
            scan_info['return_code'] = result.returncode
            scan_info['scan_time'] = time.time() - scan_info['start_time']

            # Nikto returns different exit codes, 0 and 2 can both indicate success
            if result.returncode in [0, 2, 3]:  # 0=no issues, 2=issues found, 3=some issues
                output = result.stdout
                scan_info['raw_output'] = output[:2000]  # Truncate for storage

                # Parse Nikto output
                lines = output.split('\n')
                findings = []

                for line in lines:
                    line = line.strip()

                    # Look for vulnerability findings (lines starting with +)
                    if line.startswith('+ ') and len(line) > 10:
                        finding = line[2:].strip()  # Remove '+ ' prefix

                        # Skip informational lines
                        if any(skip in finding.lower() for skip in ['target ip:', 'start time:', 'server:', 'retrieved']):
                            continue

                        findings.append(finding)

                        # Categorize findings by severity
                        risk_level = self._categorize_nikto_finding(finding)

                        vulnerabilities.append({
                            'name': 'Web Server Vulnerability',
                            'description': finding,
                            'risk_level': risk_level,
                            'url': target_url,
                            'evidence': finding,
                            'solution': 'Review and remediate the identified web server issue',
                            'scanner': 'Nikto'
                        })

                scan_info['findings_count'] = len(findings)
                scan_info['unique_findings'] = len(set(findings))

                logger.info(f"Nikto scan completed: {len(findings)} findings")

                return {
                    'vulnerabilities': vulnerabilities,
                    'scan_info': scan_info
                }
            else:
                error_msg = result.stderr or f'Nikto scan failed with exit code {result.returncode}'
                logger.error(f"Nikto scan failed: {error_msg}")
                return {
                    'error': f'Nikto scan failed: {error_msg}',
                    'vulnerabilities': [],
                    'scan_info': scan_info
                }

        except subprocess.TimeoutExpired:
            logger.error("Nikto scan timed out")
            return {
                'error': 'Nikto scan timed out after 5 minutes',
                'vulnerabilities': [],
                'scan_info': scan_info
            }
        except FileNotFoundError:
            logger.error("Nikto not found")
            return {
                'error': 'Nikto not installed or not found in PATH',
                'vulnerabilities': [],
                'scan_info': scan_info
            }
        except Exception as e:
            logger.error(f"Nikto scan error: {str(e)}")
            return {
                'error': f'Nikto scan error: {str(e)}',
                'vulnerabilities': [],
                'scan_info': scan_info
            }

    def _categorize_nikto_finding(self, finding: str) -> str:
        """Categorize Nikto finding by risk level"""
        finding_lower = finding.lower()

        # High risk indicators
        high_risk_keywords = [
            'sql injection', 'xss', 'script injection', 'command injection',
            'path traversal', 'directory traversal', 'file inclusion',
            'authentication bypass', 'admin', 'password', 'credential',
            'backdoor', 'shell', 'exploit'
        ]

        # Medium risk indicators
        medium_risk_keywords = [
            'configuration', 'backup', 'sensitive', 'information disclosure',
            'debug', 'error', 'exception', 'test', 'temp', 'old'
        ]

        # Check for high risk
        if any(keyword in finding_lower for keyword in high_risk_keywords):
            return 'high'

        # Check for medium risk
        if any(keyword in finding_lower for keyword in medium_risk_keywords):
            return 'medium'

        # Default to low risk
        return 'low'

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
                summary['by_scanner'][scanner_name] = {
                    'total': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0,
                    'status': 'error', 'error': results['error']
                }
                continue

            vulnerabilities = results.get('vulnerabilities', [])
            scanner_summary = {
                'total': len(vulnerabilities),
                'high': 0, 'medium': 0, 'low': 0, 'info': 0,
                'status': 'success'
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
            'URL', 'Evidence', 'Solution', 'Timestamp'
        ])

        # Write scan metadata
        writer.writerow([
            'SCAN_INFO', 'Target URL', 'N/A', scan_results.get('target_url', ''),
            '', '', '', scan_results.get('timestamp', '')
        ])

        # Write vulnerability data
        scanner_results = scan_results.get('scanner_results', {})

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
                    scan_results.get('timestamp', '')
                ])

        # Write summary section
        writer.writerow([])
        writer.writerow(['SUMMARY', 'Total Vulnerabilities', '', 
                        str(scan_results.get('summary', {}).get('total_vulnerabilities', 0))])

        return output.getvalue()

    def get_scanner_status(self) -> dict:
        """Get status of all scanners"""
        status = {}

        # Check if tools are available
        tools = {
            'basic': {'cmd': None, 'always_available': True},
            'nmap': {'cmd': ['nmap', '--version'], 'always_available': False},
            'nikto': {'cmd': ['nikto', '-Version'], 'always_available': False}
        }

        for tool_name, tool_info in tools.items():
            if tool_info['always_available']:
                status[tool_name] = {
                    'available': True,
                    'status': 'ready',
                    'version': 'Built-in scanner'
                }
            else:
                try:
                    result = subprocess.run(tool_info['cmd'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode in [0, 2]:  # Nikto can return 2
                        version_info = result.stdout.split('\n')[0] if result.stdout else 'Available'
                        status[tool_name] = {
                            'available': True,
                            'status': 'ready',
                            'version': version_info
                        }
                    else:
                        status[tool_name] = {
                            'available': False,
                            'status': 'error',
                            'error': 'Command failed'
                        }
                except Exception as e:
                    status[tool_name] = {
                        'available': False,
                        'status': 'not_found',
                        'error': str(e)
                    }

        return status

    def health_check(self) -> dict:
        """Perform health check on all scanners"""
        health = {
            'overall_status': 'healthy',
            'scanners': {},
            'timestamp': datetime.now().isoformat(),
            'available_scanners': self.available_scanners
        }

        scanner_status = self.get_scanner_status()

        for scanner_name, status in scanner_status.items():
            if status.get('available', False):
                health['scanners'][scanner_name] = {
                    'status': 'healthy', 
                    'version': status.get('version', 'Unknown')
                }
            else:
                health['scanners'][scanner_name] = {
                    'status': 'unavailable', 
                    'error': status.get('error', 'Unknown error')
                }

        # Overall status is healthy if at least basic scanner works
        if 'basic' not in health['scanners'] or health['scanners']['basic']['status'] != 'healthy':
            health['overall_status'] = 'degraded'

        return health
