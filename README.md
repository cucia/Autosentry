# 🛡️ AutoSentry - VAPT Tool

**AutoSentry** is a comprehensive Vulnerability Assessment and Penetration Testing (VAPT) tool that integrates multiple security scanners including Nmap, Nikto, and custom web vulnerability checks for local scanning capabilities.

## 🌟 Features

- **🔍 Multi-Scanner Integration**: Combines Nmap, Nikto, and custom web scanners
- **🌐 Professional Web Dashboard**: Easy-to-use web interface
- **⚡ Real-time Scanning**: Live vulnerability detection and reporting  
- **📊 Detailed Reports**: Comprehensive vulnerability assessment reports
- **🔌 API Interface**: RESTful API for automation and integration
- **💻 Command Line Interface**: CLI tool for scripting and automation
- **📈 Risk Assessment**: Categorizes vulnerabilities by risk level
- **🏠 Local Scanning**: No external API dependencies - unlimited scans
- **📋 Export Capabilities**: Results in JSON and CSV formats

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# Install Python packages
pip install -r config/requirements.txt

# Install system tools (Ubuntu/Debian)
sudo apt update
sudo apt install nmap nikto

# For other systems:
# CentOS/RHEL: sudo yum install nmap nikto
# macOS: brew install nmap nikto
```

### 2. Configure AutoSentry

```bash
# Copy configuration template
cp config/.env.example config/.env

# Edit configuration (optional - defaults work fine)
nano config/.env
```

### 3. Run Setup Check

```bash
python main.py setup
```

### 4. Start the Server

```bash
python main.py server
```

### 5. Access Web Interface

Open your browser to: **http://localhost:5000**

## 🖥️ Usage

### Web Interface

1. Open http://localhost:5000
2. Enter target URL (e.g., `https://example.com`)  
3. Select scan type:
   - **Basic**: Web security headers and basic checks
   - **Nmap**: Network and port scanning
   - **Nikto**: Web server vulnerability scanning
   - **Full**: All scanners combined
4. Click "Start Scan" and view results

### Command Line Interface

```bash
# Check server health
python main.py client health

# Check scanner status
python main.py client status

# Start a basic web scan
python main.py client scan https://example.com --type basic

# Start a full assessment
python main.py client scan https://example.com --type full --detailed

# Get help
python main.py client --help
```

### API Usage

```bash
# Start scan via API
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "scan_type": "basic"}'

# Check server health
curl http://localhost:5000/health

# Check scanner status  
curl http://localhost:5000/api/scanner-status
```

## 🔧 Configuration

### Environment Variables

Key settings in `config/.env`:

```bash
# Server settings
AUTOSENTRY_HOST=0.0.0.0
AUTOSENTRY_PORT=5000
AUTOSENTRY_DEBUG=True

# Scanner settings  
ENABLE_NMAP=True
ENABLE_NIKTO=True
MAX_SCAN_TIME=1800

# Directories
RESULTS_DIR=./results
LOGS_DIR=./logs
TEMP_DIR=./temp
```

### Scanner Configuration

- **Nmap**: Network and port scanning
- **Nikto**: Web server vulnerability assessment
- **Basic Web Scanner**: HTTP security headers, cookies, server info

## 📊 Scan Types

- **Basic**: Fast web security check (security headers, server info)
- **Nmap**: Network scan (open ports, services, OS detection)
- **Nikto**: Web vulnerability scan (6700+ vulnerability checks)
- **Full**: Combined scan using all available scanners

## 🛡️ Security Considerations

⚠️ **IMPORTANT**: Only scan systems you own or have explicit permission to test.

- Use for authorized security assessments only
- Follow responsible disclosure practices
- Comply with local laws and regulations
- Consider using in isolated test environments

## 📁 Project Structure

```
autosentry/
├── main.py              # Main entry point
├── server/
│   ├── app.py           # Flask web application
│   ├── vapt_scanner.py  # Main scanner orchestrator
│   ├── config.py        # Configuration management
│   └── utils.py         # Utility functions
├── client/
│   └── client.py        # Command-line client
├── config/
│   ├── .env.example     # Configuration template
│   ├── .env             # Your configuration
│   └── requirements.txt # Python dependencies
├── docs/
│   └── README.md        # This file
├── results/             # Scan results storage
├── logs/                # Application logs
└── temp/                # Temporary files
```

## 🔍 Vulnerability Detection

AutoSentry can detect:

### Web Application Security
- Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
- Server information disclosure
- Insecure cookie configurations
- Common web server misconfigurations

### Network Security  
- Open ports and services
- Service version information
- Potentially insecure services (FTP, Telnet)
- Network service enumeration

### Web Server Vulnerabilities
- 6700+ known vulnerability checks (via Nikto)
- Dangerous files and directories
- Server-specific vulnerabilities
- Web application framework issues

## 📈 Risk Assessment

Vulnerabilities are categorized by risk level:

- **🔴 High Risk**: Critical vulnerabilities requiring immediate attention
- **🟡 Medium Risk**: Important security issues to address
- **🟢 Low Risk**: Minor security improvements
- **ℹ️ Info**: Informational findings for awareness

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)  
5. Open a Pull Request

## 🐛 Troubleshooting

### Common Issues

**1. "Module not found" errors**
```bash
pip install -r config/requirements.txt
```

**2. "Scanner not found" errors**
```bash
# Install missing scanners
sudo apt install nmap nikto  # Ubuntu/Debian
brew install nmap nikto      # macOS
```

**3. Permission denied errors**
```bash
# Don't run as root unless necessary
# Ensure proper file permissions
chmod +x main.py
```

**4. Port already in use**
```bash
# Change port in config/.env
AUTOSENTRY_PORT=5001
```

### Getting Help

1. Check the setup: `python main.py setup`
2. Review logs in `logs/autosentry.log`  
3. Test individual components:
   - Server: `python main.py server`
   - Client: `python main.py client health`
4. Check scanner status: `python main.py client status`

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **OWASP** for security standards and best practices
- **Nmap Project** for the excellent network scanner
- **Nikto** team for the comprehensive web vulnerability scanner
- **Flask** team for the fantastic web framework

## 🔄 Roadmap

- [ ] OWASP ZAP integration
- [ ] Database storage for scan history
- [ ] User authentication and multi-user support
- [ ] Scheduled scanning capabilities
- [ ] Custom vulnerability rules
- [ ] Integration with CI/CD pipelines
- [ ] Docker containerization
- [ ] PDF report generation

---

**🛡️ Stay Secure! Happy Scanning!**

For more information, visit: [AutoSentry Documentation](docs/)
