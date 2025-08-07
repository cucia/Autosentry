#!/usr/bin/env python3
"""
AutoSentry - Vulnerability Assessment and Penetration Testing Tool
Main Server Application (Fixed Version)

This is a comprehensive VAPT tool that integrates multiple vulnerability scanners
including OWASP ZAP, Nmap, and Nikto for local scanning capabilities.
"""

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import logging
import os
import sys
from datetime import datetime
import threading
import traceback

# Add current directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)
sys.path.insert(0, current_dir)

try:
    from vapt_scanner import VAPTScanner
    from utils import setup_logging, validate_url
    from config import Config
except ImportError as e:
    print(f"Import error: {e}")
    print("Creating minimal implementations...")

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize scanner (with error handling)
try:
    vapt_scanner = VAPTScanner()
except:
    vapt_scanner = None
    logger.warning("VAPT Scanner not available, using basic functionality")

# Store scan results in memory
scan_results = {}
active_scans = {}

@app.route('/')
def index():
    """Main dashboard"""
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>AutoSentry - VAPT Tool Dashboard</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            .container { 
                max-width: 1200px; 
                margin: 0 auto; 
                background: white; 
                padding: 30px; 
                border-radius: 15px; 
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            }
            h1 { 
                color: #2c3e50; 
                text-align: center; 
                margin-bottom: 30px;
                font-size: 2.5em;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
            }
            .scan-form { 
                background: #f8f9fa; 
                padding: 25px; 
                border-radius: 10px; 
                margin: 20px 0;
                border: 1px solid #e9ecef;
            }
            .form-group { margin: 15px 0; }
            label { 
                display: block; 
                margin-bottom: 5px; 
                font-weight: 600;
                color: #495057;
            }
            input[type="url"], select { 
                width: 100%; 
                padding: 12px; 
                border: 2px solid #ced4da;
                border-radius: 8px; 
                font-size: 16px;
                transition: border-color 0.3s;
            }
            input[type="url"]:focus, select:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }
            .btn { 
                background: linear-gradient(45deg, #667eea, #764ba2);
                color: white; 
                padding: 12px 30px; 
                border: none; 
                border-radius: 8px; 
                cursor: pointer;
                font-size: 16px;
                font-weight: 600;
                transition: transform 0.2s;
            }
            .btn:hover { 
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            }
            .results { 
                margin-top: 20px; 
                padding: 20px; 
                background: #f8f9fa; 
                border-radius: 10px;
                border: 1px solid #e9ecef;
            }
            .status { 
                padding: 15px; 
                margin: 10px 0; 
                border-radius: 8px;
                font-weight: 500;
            }
            .success { 
                background: #d4edda; 
                border: 1px solid #c3e6cb; 
                color: #155724; 
            }
            .error { 
                background: #f8d7da; 
                border: 1px solid #f5c6cb; 
                color: #721c24; 
            }
            .info { 
                background: #d1ecf1; 
                border: 1px solid #bee5eb; 
                color: #0c5460; 
            }
            .loading { 
                background: #fff3cd; 
                border: 1px solid #ffeaa7; 
                color: #856404; 
            }
            pre { 
                background: #2c3e50; 
                color: #ecf0f1; 
                padding: 20px; 
                border-radius: 8px; 
                overflow-x: auto;
                font-size: 14px;
                line-height: 1.5;
            }
            .stats { 
                display: grid; 
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                gap: 15px; 
                margin: 20px 0; 
            }
            .stat-card { 
                background: white; 
                padding: 20px; 
                border-radius: 8px; 
                text-align: center;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .stat-number { 
                font-size: 2em; 
                font-weight: bold; 
                color: #667eea; 
            }
            .footer { 
                text-align: center; 
                margin-top: 30px; 
                padding-top: 20px; 
                border-top: 1px solid #e9ecef;
                color: #6c757d;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ AutoSentry - VAPT Tool</h1>

            <div class="scan-form">
                <h3>🔍 Start Vulnerability Assessment</h3>
                <form id="scanForm">
                    <div class="form-group">
                        <label for="targetUrl">Target URL:</label>
                        <input type="url" id="targetUrl" placeholder="https://example.com" required>
                    </div>
                    <div class="form-group">
                        <label for="scanType">Scan Type:</label>
                        <select id="scanType">
                            <option value="basic">Basic Web Security Check</option>
                            <option value="nmap">Network Scan (Nmap)</option>
                            <option value="nikto">Web Vulnerability Scan (Nikto)</option>
                            <option value="full">Full Assessment (All Scanners)</option>
                        </select>
                    </div>
                    <button type="submit" class="btn">🚀 Start Scan</button>
                </form>
            </div>

            <div id="results" class="results" style="display:none;">
                <h3>📊 Scan Results</h3>
                <div id="resultContent"></div>
            </div>

            <div class="footer">
                <p>🔒 AutoSentry VAPT Tool - Professional Vulnerability Assessment Platform</p>
                <p>API Health: <a href="/health">Check Status</a> | Scanner Status: <a href="/api/scanner-status">View Details</a></p>
            </div>
        </div>

        <script>
            document.getElementById('scanForm').addEventListener('submit', function(e) {
                e.preventDefault();

                const url = document.getElementById('targetUrl').value;
                const scanType = document.getElementById('scanType').value;

                // Show loading
                const results = document.getElementById('results');
                const content = document.getElementById('resultContent');
                results.style.display = 'block';
                content.innerHTML = '<div class="status loading">🔄 Initiating ' + scanType + ' scan for ' + url + '...<br>This may take a few moments.</div>';

                // Start scan
                fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url, scan_type: scanType})
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        content.innerHTML = '<div class="status success">✅ Scan completed successfully!</div>';

                        // Display results with statistics
                        if (data.results) {
                            let resultHtml = '<h4>🔍 Vulnerability Assessment Report:</h4>';

                            // Add statistics
                            if (data.results.summary) {
                                const summary = data.results.summary;
                                resultHtml += '<div class="stats">';
                                resultHtml += '<div class="stat-card"><div class="stat-number">' + summary.total_vulnerabilities + '</div>Total Findings</div>';
                                resultHtml += '<div class="stat-card"><div class="stat-number">' + (summary.high_risk || 0) + '</div>High Risk</div>';
                                resultHtml += '<div class="stat-card"><div class="stat-number">' + (summary.medium_risk || 0) + '</div>Medium Risk</div>';
                                resultHtml += '<div class="stat-card"><div class="stat-number">' + (summary.low_risk || 0) + '</div>Low Risk</div>';
                                resultHtml += '</div>';
                            }

                            // Add detailed results
                            for (const [scanner, result] of Object.entries(data.results.scanner_results || {})) {
                                resultHtml += '<h5>📋 ' + scanner.toUpperCase() + ' Results:</h5>';
                                if (result.error) {
                                    resultHtml += '<div class="status error">Error: ' + result.error + '</div>';
                                } else {
                                    resultHtml += '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
                                }
                            }

                            content.innerHTML += resultHtml;
                        }
                    } else {
                        content.innerHTML = '<div class="status error">❌ Scan failed: ' + (data.error || 'Unknown error') + '</div>';
                    }
                })
                .catch(error => {
                    content.innerHTML = '<div class="status error">❌ Network error: ' + error.message + '</div>';
                });
            });
        </script>
    </body>
    </html>
    """
    return render_template_string(html_template)

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a vulnerability scan"""
    try:
        data = request.get_json()
        target_url = data.get('url')
        scan_type = data.get('scan_type', 'basic')

        # Basic URL validation
        if not target_url or not target_url.startswith(('http://', 'https://')):
            return jsonify({'success': False, 'error': 'Invalid URL format'})

        logger.info(f"Starting {scan_type} scan for {target_url}")

        # Use VAPT scanner if available, otherwise use basic scanning
        if vapt_scanner:
            try:
                results = vapt_scanner.scan(target_url, scan_type)
            except Exception as e:
                logger.error(f"VAPT scanner error: {e}")
                results = perform_basic_scan(target_url, scan_type)
        else:
            results = perform_basic_scan(target_url, scan_type)

        # Store results with timestamp
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        scan_results[scan_id] = {
            'url': target_url,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'results': results
        }

        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'results': results
        })

    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)})

def perform_basic_scan(target_url, scan_type):
    """Perform basic vulnerability scan when full scanner is not available"""
    try:
        import requests
        import subprocess
        from urllib.parse import urlparse

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

        vulnerabilities = []

        if scan_type in ['basic', 'full']:
            # Basic web security check
            try:
                response = requests.get(target_url, timeout=10, verify=False)

                # Check security headers
                security_headers = {
                    'X-Frame-Options': 'Missing X-Frame-Options header (Clickjacking protection)',
                    'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                    'X-XSS-Protection': 'Missing X-XSS-Protection header',
                    'Strict-Transport-Security': 'Missing HSTS header',
                    'Content-Security-Policy': 'Missing CSP header'
                }

                for header, description in security_headers.items():
                    if header not in response.headers:
                        vulnerabilities.append({
                            'name': f'Missing Security Header: {header}',
                            'description': description,
                            'risk_level': 'medium' if header in ['X-Frame-Options', 'Content-Security-Policy'] else 'low',
                            'url': target_url,
                            'evidence': f'Header {header} not found in response',
                            'solution': f'Add {header} header to web server configuration',
                            'scanner': 'Basic Web Scanner'
                        })

                # Check server information disclosure
                if 'Server' in response.headers:
                    vulnerabilities.append({
                        'name': 'Server Information Disclosure',
                        'description': f'Server banner reveals: {response.headers["Server"]}',
                        'risk_level': 'info',
                        'url': target_url,
                        'evidence': f'Server: {response.headers["Server"]}',
                        'solution': 'Configure web server to hide version information',
                        'scanner': 'Basic Web Scanner'
                    })

                results['scanner_results']['basic'] = {
                    'vulnerabilities': vulnerabilities,
                    'scan_info': {
                        'status_code': response.status_code,
                        'response_headers': dict(response.headers),
                        'scanner': 'Basic Web Scanner'
                    }
                }

            except Exception as e:
                results['scanner_results']['basic'] = {
                    'error': f'Basic scan failed: {str(e)}',
                    'vulnerabilities': []
                }

        if scan_type in ['nmap', 'full']:
            # Try Nmap scan
            try:
                parsed_url = urlparse(target_url)
                host = parsed_url.hostname

                # Simple nmap scan
                cmd = ['nmap', '-T4', '-F', host]  # Fast scan of most common ports
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

                if result.returncode == 0:
                    # Parse nmap output for open ports
                    nmap_vulns = []
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '/tcp' in line and 'open' in line:
                            port_info = line.strip()
                            nmap_vulns.append({
                                'name': 'Open Port Detected',
                                'description': f'Open port found: {port_info}',
                                'risk_level': 'info',
                                'url': f'tcp://{host}',
                                'evidence': port_info,
                                'solution': 'Review if this port needs to be publicly accessible',
                                'scanner': 'Nmap'
                            })

                    vulnerabilities.extend(nmap_vulns)
                    results['scanner_results']['nmap'] = {
                        'vulnerabilities': nmap_vulns,
                        'scan_info': {'output': result.stdout, 'scanner': 'Nmap'}
                    }
                else:
                    results['scanner_results']['nmap'] = {
                        'error': 'Nmap scan failed or host unreachable',
                        'vulnerabilities': []
                    }

            except Exception as e:
                results['scanner_results']['nmap'] = {
                    'error': f'Nmap not available or failed: {str(e)}',
                    'vulnerabilities': []
                }

        if scan_type in ['nikto', 'full']:
            # Try Nikto scan
            try:
                cmd = ['nikto', '-h', target_url, '-Format', 'txt']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

                if result.returncode in [0, 2]:  # Nikto returns 2 on findings
                    # Parse nikto output
                    nikto_vulns = []
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if line.startswith('+ ') and ':' in line:
                            finding = line[2:].strip()  # Remove '+ ' prefix
                            nikto_vulns.append({
                                'name': 'Web Server Finding',
                                'description': finding,
                                'risk_level': 'low',
                                'url': target_url,
                                'evidence': finding,
                                'solution': 'Review and remediate the identified issue',
                                'scanner': 'Nikto'
                            })

                    vulnerabilities.extend(nikto_vulns)
                    results['scanner_results']['nikto'] = {
                        'vulnerabilities': nikto_vulns,
                        'scan_info': {'findings_count': len(nikto_vulns), 'scanner': 'Nikto'}
                    }
                else:
                    results['scanner_results']['nikto'] = {
                        'error': 'Nikto scan failed',
                        'vulnerabilities': []
                    }

            except Exception as e:
                results['scanner_results']['nikto'] = {
                    'error': f'Nikto not available or failed: {str(e)}',
                    'vulnerabilities': []
                }

        # Calculate summary
        risk_counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in vulnerabilities:
            risk_level = vuln.get('risk_level', 'info')
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1

        results['summary'] = {
            'total_vulnerabilities': len(vulnerabilities),
            'high_risk': risk_counts['high'],
            'medium_risk': risk_counts['medium'],
            'low_risk': risk_counts['low'],
            'info': risk_counts['info']
        }

        return results

    except Exception as e:
        logger.error(f"Basic scan error: {e}")
        return {
            'error': str(e),
            'scanner_results': {},
            'summary': {'total_vulnerabilities': 0}
        }

@app.route('/api/results/<scan_id>')
def get_results(scan_id):
    """Get scan results by ID"""
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/scanner-status')
def scanner_status():
    """Get status of all scanners"""
    status = {}

    # Check Nmap
    try:
        import subprocess
        result = subprocess.run(['nmap', '--version'], capture_output=True, timeout=5)
        status['nmap'] = {
            'available': result.returncode == 0,
            'version': result.stdout.decode().split('\n')[0] if result.returncode == 0 else 'Not found'
        }
    except:
        status['nmap'] = {'available': False, 'error': 'Not installed'}

    # Check Nikto
    try:
        result = subprocess.run(['nikto', '-Version'], capture_output=True, timeout=5)
        status['nikto'] = {
            'available': result.returncode == 0,
            'version': result.stdout.decode().split('\n')[0] if result.returncode == 0 else 'Not found'
        }
    except:
        status['nikto'] = {'available': False, 'error': 'Not installed'}

    # Check Java (for ZAP)
    try:
        result = subprocess.run(['java', '-version'], capture_output=True, timeout=5)
        status['java'] = {
            'available': result.returncode == 0,
            'version': result.stderr.decode().split('\n')[0] if result.returncode == 0 else 'Not found'
        }
    except:
        status['java'] = {'available': False, 'error': 'Not installed'}

    return jsonify({
        'scanners': status,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'scanner_available': vapt_scanner is not None
    })

@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors"""
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(404)
def not_found(error):
    """Handle not found errors"""
    return jsonify({'error': 'Endpoint not found'}), 404

if __name__ == '__main__':
    # Load configuration
    try:
        config = Config()
        host = config.HOST
        port = config.PORT
        debug = config.DEBUG
    except:
        # Fallback configuration
        host = os.getenv('AUTOSENTRY_HOST', '0.0.0.0')
        port = int(os.getenv('AUTOSENTRY_PORT', '5000'))
        debug = os.getenv('AUTOSENTRY_DEBUG', 'True').lower() == 'true'

    # Start server
    logger.info("Starting AutoSentry VAPT Tool Server...")
    logger.info(f"Server will be available at: http://{host}:{port}")

    app.run(
        host=host,
        port=port,
        debug=debug
    )
