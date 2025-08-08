#!/usr/bin/env python3
"""
AutoSentry - Vulnerability Assessment and Penetration Testing Tool
Main Server Application (Fixed Version with Working Nmap/Nikto)
"""

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import logging
import os
import sys
from datetime import datetime
import threading
import traceback
import json

# Add paths for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)
sys.path.insert(0, current_dir)

try:
    from vapt_scanner import VAPTScanner
    from utils import setup_logging, validate_url
    from config import Config
except ImportError:
    print("Warning: Some modules could not be imported, using fallbacks...")

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize scanner (with error handling)
try:
    vapt_scanner = VAPTScanner()
    logger.info("VAPT Scanner initialized successfully")
except Exception as e:
    vapt_scanner = None
    logger.error(f"VAPT Scanner initialization failed: {e}")

# Store scan results in memory
scan_results = {}
active_scans = {}

@app.route('/')
def index():
    """Main dashboard with improved UI"""
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
            .scanner-status {
                background: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                margin-bottom: 20px;
                border: 1px solid #e9ecef;
            }
            .status-item {
                display: inline-block;
                margin: 5px 10px;
                padding: 5px 10px;
                border-radius: 20px;
                font-size: 14px;
                font-weight: 600;
            }
            .status-available { background: #d4edda; color: #155724; }
            .status-unavailable { background: #f8d7da; color: #721c24; }
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
            .btn:disabled {
                opacity: 0.6;
                cursor: not-allowed;
                transform: none;
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
            .success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
            .error { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
            .info { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }
            .loading { background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
            pre { 
                background: #2c3e50; 
                color: #ecf0f1; 
                padding: 20px; 
                border-radius: 8px; 
                overflow-x: auto;
                font-size: 14px;
                line-height: 1.5;
                max-height: 400px;
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
            .stat-number { font-size: 2em; font-weight: bold; }
            .high-risk { color: #dc3545; }
            .medium-risk { color: #fd7e14; }
            .low-risk { color: #ffc107; }
            .info-risk { color: #17a2b8; }
            .footer { 
                text-align: center; 
                margin-top: 30px; 
                padding-top: 20px; 
                border-top: 1px solid #e9ecef;
                color: #6c757d;
            }
            .progress-bar {
                width: 100%;
                height: 20px;
                background: #e9ecef;
                border-radius: 10px;
                overflow: hidden;
                margin: 10px 0;
            }
            .progress-fill {
                height: 100%;
                background: linear-gradient(45deg, #667eea, #764ba2);
                width: 0%;
                transition: width 0.5s ease;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ AutoSentry - VAPT Tool</h1>

            <div class="scanner-status">
                <h3>🔍 Scanner Status</h3>
                <div id="scannerStatus">Loading scanner status...</div>
            </div>

            <div class="scan-form">
                <h3>🔍 Start Vulnerability Assessment</h3>
                <form id="scanForm">
                    <div class="form-group">
                        <label for="targetUrl">Target URL:</label>
                        <input type="url" id="targetUrl" placeholder="https://example.com" required>
                        <small>Enter the complete URL including http:// or https://</small>
                    </div>
                    <div class="form-group">
                        <label for="scanType">Scan Type:</label>
                        <select id="scanType">
                            <option value="basic">Basic Web Security Check (Fast)</option>
                            <option value="nmap">Network Scan (Nmap)</option>
                            <option value="nikto">Web Vulnerability Scan (Nikto)</option>
                            <option value="full">Full Assessment (All Scanners)</option>
                        </select>
                    </div>
                    <button type="submit" class="btn" id="scanButton">🚀 Start Scan</button>
                    <div class="progress-bar" id="progressBar" style="display: none;">
                        <div class="progress-fill" id="progressFill"></div>
                    </div>
                </form>
            </div>

            <div id="results" class="results" style="display:none;">
                <h3>📊 Scan Results</h3>
                <div id="resultContent"></div>
            </div>

            <div class="footer">
                <p>🔒 AutoSentry VAPT Tool - Professional Vulnerability Assessment Platform</p>
                <p>API Health: <a href="/health">Check Status</a> | Scanner Status: <a href="/api/scanner-status">View Details</a></p>
                <p>Client Usage: <code>python main.py client scan https://example.com</code></p>
            </div>
        </div>

        <script>
            // Load scanner status on page load
            async function loadScannerStatus() {
                try {
                    const response = await fetch('/api/scanner-status');
                    const data = await response.json();
                    const statusDiv = document.getElementById('scannerStatus');

                    let statusHtml = '';
                    for (const [scanner, info] of Object.entries(data.scanners || {})) {
                        const statusClass = info.available ? 'status-available' : 'status-unavailable';
                        const statusText = info.available ? 'Available' : 'Unavailable';
                        statusHtml += `<span class="status-item ${statusClass}">${scanner.toUpperCase()}: ${statusText}</span>`;
                    }

                    statusDiv.innerHTML = statusHtml;
                } catch (error) {
                    document.getElementById('scannerStatus').innerHTML = '<span class="status-item status-unavailable">Error loading scanner status</span>';
                }
            }

            // Simulate progress bar
            function simulateProgress() {
                const progressBar = document.getElementById('progressBar');
                const progressFill = document.getElementById('progressFill');

                progressBar.style.display = 'block';
                let progress = 0;

                const interval = setInterval(() => {
                    progress += Math.random() * 10;
                    if (progress > 90) progress = 90;
                    progressFill.style.width = progress + '%';
                }, 500);

                return interval;
            }

            // Handle form submission
            document.getElementById('scanForm').addEventListener('submit', async function(e) {
                e.preventDefault();

                const url = document.getElementById('targetUrl').value;
                const scanType = document.getElementById('scanType').value;
                const button = document.getElementById('scanButton');
                const results = document.getElementById('results');
                const content = document.getElementById('resultContent');

                // Disable button and show loading
                button.disabled = true;
                button.textContent = '🔄 Scanning...';

                results.style.display = 'block';
                content.innerHTML = '<div class="status loading">🔄 Initiating ' + scanType + ' scan for ' + url + '...<br>This may take a few moments depending on the scan type.</div>';

                const progressInterval = simulateProgress();

                try {
                    const response = await fetch('/api/scan', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({url: url, scan_type: scanType})
                    });

                    const data = await response.json();

                    // Clear progress bar
                    clearInterval(progressInterval);
                    document.getElementById('progressBar').style.display = 'none';

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
                                resultHtml += '<div class="stat-card"><div class="stat-number high-risk">' + (summary.high_risk || 0) + '</div>High Risk</div>';
                                resultHtml += '<div class="stat-card"><div class="stat-number medium-risk">' + (summary.medium_risk || 0) + '</div>Medium Risk</div>';
                                resultHtml += '<div class="stat-card"><div class="stat-number low-risk">' + (summary.low_risk || 0) + '</div>Low Risk</div>';
                                resultHtml += '<div class="stat-card"><div class="stat-number info-risk">' + (summary.info || 0) + '</div>Info</div>';
                                resultHtml += '</div>';
                            }

                            // Add scanner-specific results
                            const scannerResults = data.results.scanner_results || {};
                            for (const [scanner, result] of Object.entries(scannerResults)) {
                                resultHtml += '<h5>📋 ' + scanner.toUpperCase() + ' Results:</h5>';

                                if (result.error) {
                                    resultHtml += '<div class="status error">❌ ' + result.error + '</div>';
                                } else {
                                    const vulns = result.vulnerabilities || [];
                                    resultHtml += '<div class="status info">Found ' + vulns.length + ' findings</div>';

                                    if (vulns.length > 0) {
                                        resultHtml += '<div style="max-height: 300px; overflow-y: auto;">';
                                        vulns.forEach((vuln, index) => {
                                            const riskClass = vuln.risk_level === 'high' ? 'high-risk' : 
                                                            vuln.risk_level === 'medium' ? 'medium-risk' : 
                                                            vuln.risk_level === 'low' ? 'low-risk' : 'info-risk';
                                            resultHtml += '<div style="margin: 10px 0; padding: 10px; background: white; border-radius: 5px;">';
                                            resultHtml += '<strong class="' + riskClass + '">' + (vuln.name || 'Finding') + '</strong><br>';
                                            resultHtml += '<small>' + (vuln.description || 'No description') + '</small>';
                                            resultHtml += '</div>';
                                        });
                                        resultHtml += '</div>';
                                    }
                                }
                            }

                            content.innerHTML += resultHtml;
                        }
                    } else {
                        content.innerHTML = '<div class="status error">❌ Scan failed: ' + (data.error || 'Unknown error') + '</div>';
                    }
                } catch (error) {
                    clearInterval(progressInterval);
                    document.getElementById('progressBar').style.display = 'none';
                    content.innerHTML = '<div class="status error">❌ Network error: ' + error.message + '</div>';
                } finally {
                    // Re-enable button
                    button.disabled = false;
                    button.textContent = '🚀 Start Scan';
                }
            });

            // Load scanner status when page loads
            loadScannerStatus();
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
        if not data:
            return jsonify({'success': False, 'error': 'No JSON data provided'})

        target_url = data.get('url')
        scan_type = data.get('scan_type', 'basic')

        # Validate input
        if not target_url:
            return jsonify({'success': False, 'error': 'URL is required'})

        if not target_url.startswith(('http://', 'https://')):
            return jsonify({'success': False, 'error': 'URL must include http:// or https://'})

        logger.info(f"Starting {scan_type} scan for {target_url}")

        # Use VAPT scanner if available
        if vapt_scanner:
            try:
                results = vapt_scanner.scan(target_url, scan_type)
            except Exception as e:
                logger.error(f"VAPT scanner error: {e}")
                return jsonify({'success': False, 'error': f'Scanner error: {str(e)}'})
        else:
            return jsonify({'success': False, 'error': 'VAPT scanner not available'})

        # Store results with timestamp
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        scan_results[scan_id] = {
            'url': target_url,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'results': results
        }

        logger.info(f"Scan completed: {scan_id}")

        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'results': results
        })

    except Exception as e:
        logger.error(f"Scan API error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': f'Internal error: {str(e)}'})

@app.route('/api/results/<scan_id>')
def get_results(scan_id):
    """Get scan results by ID"""
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/scanner-status')
def scanner_status():
    """Get status of all scanners"""
    try:
        if vapt_scanner:
            status = vapt_scanner.get_scanner_status()
            return jsonify({
                'scanners': status,
                'timestamp': datetime.now().isoformat(),
                'server_status': 'healthy'
            })
        else:
            return jsonify({
                'scanners': {
                    'basic': {'available': True, 'status': 'ready'},
                    'nmap': {'available': False, 'error': 'Scanner not initialized'},
                    'nikto': {'available': False, 'error': 'Scanner not initialized'}
                },
                'timestamp': datetime.now().isoformat(),
                'server_status': 'degraded'
            })
    except Exception as e:
        logger.error(f"Scanner status error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        health_data = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0',
            'scanner_available': vapt_scanner is not None
        }

        if vapt_scanner:
            scanner_health = vapt_scanner.health_check()
            health_data['scanners'] = scanner_health['scanners']
            health_data['available_scanners'] = scanner_health.get('available_scanners', [])

        return jsonify(health_data)
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/api/export/<scan_id>')
def export_results(scan_id):
    """Export scan results as CSV"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404

    try:
        scan_data = scan_results[scan_id]
        if vapt_scanner:
            csv_content = vapt_scanner.export_to_csv({'results': scan_data['results']})
        else:
            # Basic CSV export
            csv_content = f"Scanner,Finding,URL,Timestamp\n"
            csv_content += f"Basic,Scan results for {scan_data['url']},{scan_data['url']},{scan_data['timestamp']}\n"

        response = app.response_class(
            csv_content,
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename={scan_id}.csv'}
        )
        return response
    except Exception as e:
        logger.error(f"Export error: {e}")
        return jsonify({'error': str(e)}), 500

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
        debug = False  # Always False for production stability
    except:
        # Fallback configuration
        host = os.getenv('AUTOSENTRY_HOST', '0.0.0.0')
        port = int(os.getenv('AUTOSENTRY_PORT', '5000'))
        debug = False

    # Start server
    logger.info("Starting AutoSentry VAPT Tool Server...")
    logger.info(f"Server will be available at: http://{host}:{port}")

    app.run(
        host=host,
        port=port,
        debug=debug,
        use_reloader=False,
        threaded=True
    )
