#!/usr/bin/env python3
"""
AutoSentry Configuration (Fixed Version)
Configuration management for the VAPT scanner
"""

import os
from typing import Dict, Any
from dotenv import load_dotenv

class Config:
    """Configuration class for AutoSentry"""

    def __init__(self):
        """Initialize configuration from environment variables"""
        # Try to load .env file
        env_paths = [
            'config/.env',
            '../config/.env',
            '.env',
            os.path.join(os.path.dirname(__file__), '..', 'config', '.env')
        ]

        for env_path in env_paths:
            if os.path.exists(env_path):
                load_dotenv(env_path)
                break

        self.load_config()

    def load_config(self):
        """Load configuration from environment variables with defaults"""
        # Server configuration
        self.HOST = os.getenv('AUTOSENTRY_HOST', '0.0.0.0')
        self.PORT = int(os.getenv('AUTOSENTRY_PORT', '5000'))
        self.DEBUG = os.getenv('AUTOSENTRY_DEBUG', 'True').lower() == 'true'

        # Logging configuration
        self.LOG_LEVEL = os.getenv('AUTOSENTRY_LOG_LEVEL', 'INFO')
        self.LOG_FILE = os.getenv('AUTOSENTRY_LOG_FILE', 'autosentry.log')

        # Scanner configuration
        self.MAX_SCAN_TIME = int(os.getenv('MAX_SCAN_TIME', '1800'))
        self.MAX_CONCURRENT_SCANS = int(os.getenv('MAX_CONCURRENT_SCANS', '3'))
        self.SCAN_TIMEOUT = int(os.getenv('SCAN_TIMEOUT', '600'))

        # Directory configuration
        self.RESULTS_DIR = os.getenv('RESULTS_DIR', './results')
        self.TEMP_DIR = os.getenv('TEMP_DIR', './temp')
        self.LOGS_DIR = os.getenv('LOGS_DIR', './logs')

        # Security configuration
        self.API_KEY = os.getenv('AUTOSENTRY_API_KEY', '')
        self.ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', '*').split(',')

        # Feature flags
        self.ENABLE_ZAP = os.getenv('ENABLE_ZAP', 'True').lower() == 'true'
        self.ENABLE_NMAP = os.getenv('ENABLE_NMAP', 'True').lower() == 'true'
        self.ENABLE_NIKTO = os.getenv('ENABLE_NIKTO', 'True').lower() == 'true'

        # Create required directories
        self._create_directories()

    def _create_directories(self):
        """Create required directories if they don't exist"""
        directories = [
            self.RESULTS_DIR,
            self.TEMP_DIR,
            self.LOGS_DIR
        ]

        for directory in directories:
            try:
                os.makedirs(directory, exist_ok=True)
            except Exception as e:
                print(f"Warning: Could not create directory {directory}: {e}")

    def validate(self) -> list:
        """Validate configuration and return list of issues"""
        issues = []

        # Check port availability
        if not (1 <= self.PORT <= 65535):
            issues.append(f"Invalid port number: {self.PORT}")

        # Check timeouts
        if self.MAX_SCAN_TIME <= 0:
            issues.append("Max scan time must be positive")

        if self.SCAN_TIMEOUT <= 0:
            issues.append("Scan timeout must be positive")

        return issues

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            'server': {
                'host': self.HOST,
                'port': self.PORT,
                'debug': self.DEBUG
            },
            'logging': {
                'level': self.LOG_LEVEL,
                'file': self.LOG_FILE
            },
            'directories': {
                'results': self.RESULTS_DIR,
                'temp': self.TEMP_DIR,
                'logs': self.LOGS_DIR
            },
            'limits': {
                'max_scan_time': self.MAX_SCAN_TIME,
                'max_concurrent_scans': self.MAX_CONCURRENT_SCANS,
                'scan_timeout': self.SCAN_TIMEOUT
            }
        }

    def __str__(self) -> str:
        """String representation of configuration"""
        return f"AutoSentry Config (Host: {self.HOST}:{self.PORT}, Debug: {self.DEBUG})"

# Global configuration instance
try:
    config = Config()
except Exception as e:
    print(f"Configuration error: {e}")
    # Create minimal fallback configuration
    class FallbackConfig:
        HOST = '0.0.0.0'
        PORT = 5000
        DEBUG = True
        LOG_LEVEL = 'INFO'

    config = FallbackConfig()
