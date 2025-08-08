#!/usr/bin/env python3
"""
AutoSentry Utility Functions (Fixed Version)
Common utility functions for the VAPT scanner
"""

import logging
import re
import os
from urllib.parse import urlparse
from typing import Optional, Dict, Any

def setup_logging(log_level: str = 'INFO') -> logging.Logger:
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('logs/autosentry.log', mode='a')
        ]
    )

    logger = logging.getLogger('autosentry')
    logger.info("Logging setup completed")

    return logger

def validate_url(url: str) -> bool:
    """Validate if URL is properly formatted"""
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme and parsed.netloc)
    except:
        return False

def sanitize_url(url: str) -> Optional[str]:
    """Sanitize and normalize URL"""
    if not url:
        return None

    url = url.strip()

    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # Validate URL
    if not validate_url(url):
        return None

    return url

def format_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """Format scan results for consistent output"""
    formatted = {
        'timestamp': results.get('timestamp', ''),
        'target': results.get('target_url', ''),
        'scan_type': results.get('scan_type', ''),
        'summary': results.get('summary', {}),
        'vulnerabilities': []
    }

    # Extract vulnerabilities from all scanners
    scanner_results = results.get('scanner_results', {})

    for scanner_name, scanner_data in scanner_results.items():
        if 'vulnerabilities' in scanner_data:
            for vuln in scanner_data['vulnerabilities']:
                vuln['scanner'] = scanner_name
                formatted['vulnerabilities'].append(vuln)

    return formatted

def get_risk_color(risk_level: str) -> str:
    """Get color code for risk level"""
    colors = {
        'critical': '#8B0000',
        'high': '#FF4500',
        'medium': '#FFA500',
        'low': '#FFD700',
        'info': '#87CEEB'
    }

    return colors.get(risk_level.lower(), '#808080')

def create_vulnerability_report(results: Dict[str, Any]) -> str:
    """Create a formatted vulnerability report"""
    report = []

    # Header
    report.append("="*80)
    report.append("AUTOSENTRY VULNERABILITY ASSESSMENT REPORT")
    report.append("="*80)
    report.append(f"Target: {results.get('target', 'N/A')}")
    report.append(f"Scan Type: {results.get('scan_type', 'N/A')}")
    report.append(f"Timestamp: {results.get('timestamp', 'N/A')}")
    report.append("")

    # Summary
    summary = results.get('summary', {})
    report.append("EXECUTIVE SUMMARY")
    report.append("-" * 20)
    report.append(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
    report.append(f"High Risk: {summary.get('high_risk', 0)}")
    report.append(f"Medium Risk: {summary.get('medium_risk', 0)}")
    report.append(f"Low Risk: {summary.get('low_risk', 0)}")
    report.append(f"Info: {summary.get('info', 0)}")
    report.append("")

    return "\n".join(report)

def extract_domain_from_url(url: str) -> str:
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return url

def is_local_ip(ip: str) -> bool:
    """Check if IP address is local/private"""
    local_patterns = [
        r'^127\.',
        r'^10\.',
        r'^192\.168\.',
        r'^172\.(1[6-9]|2[0-9]|3[01])\.'
    ]

    for pattern in local_patterns:
        if re.match(pattern, ip):
            return True

    return False

def safe_filename(filename: str) -> str:
    """Create safe filename by removing/replacing invalid characters"""
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = filename.strip('. ')

    if len(filename) > 255:
        filename = filename[:255]

    return filename or 'unnamed'

def load_config_from_env() -> Dict[str, Any]:
    """Load configuration from environment variables"""
    config = {
        'HOST': os.getenv('AUTOSENTRY_HOST', '0.0.0.0'),
        'PORT': int(os.getenv('AUTOSENTRY_PORT', '5000')),
        'DEBUG': os.getenv('AUTOSENTRY_DEBUG', 'False').lower() == 'true',
        'LOG_LEVEL': os.getenv('AUTOSENTRY_LOG_LEVEL', 'INFO'),
        'MAX_SCAN_TIME': int(os.getenv('MAX_SCAN_TIME', '1800')),
        'RESULTS_DIR': os.getenv('RESULTS_DIR', './results'),
        'TEMP_DIR': os.getenv('TEMP_DIR', './temp')
    }

    return config

def ensure_directory(path: str) -> bool:
    """Ensure directory exists, create if not"""
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except Exception as e:
        logging.error(f"Failed to create directory {path}: {e}")
        return False

def clean_string(text: str) -> str:
    """Clean string by removing control characters"""
    if not text:
        return ""

    # Remove control characters
    text = re.sub(r'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()

    return text

def truncate_text(text: str, max_length: int = 100) -> str:
    """Truncate text to maximum length with ellipsis"""
    if not text:
        return ""

    if len(text) <= max_length:
        return text

    return text[:max_length-3] + "..."
