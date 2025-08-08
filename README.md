# 🛡️ AutoSentry - Professional VAPT Tool

**AutoSentry** is a comprehensive Vulnerability Assessment and Penetration Testing (VAPT) tool that integrates multiple security scanners including **Nmap**, **Nikto**, and custom web vulnerability checks for unlimited local scanning.

## 🌟 Key Features

- **🔍 Multi-Scanner Integration**: Nmap, Nikto, and custom web scanners
- **🌐 Professional Web Dashboard**: Real-time vulnerability scanning interface
- **💻 Command Line Interface**: Full CLI client for automation
- **🎯 Python Function Interface**: Easy integration with other projects
- **📊 Multiple Output Formats**: JSON, CSV, and detailed reports
- **🏠 Local-First Architecture**: No external API dependencies = unlimited scans
- **⚡ Real-time Results**: Live vulnerability detection and reporting

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# Install Python packages
pip install Flask Flask-CORS requests python-dotenv

# Install system tools (Ubuntu/Debian)
sudo apt update && sudo apt install nmap nikto

# For other systems:
# CentOS/RHEL: sudo yum install nmap nikto
# macOS: brew install nmap nikto
```

### 2. Run Setup Check

```bash
python main.py setup
```

### 3. Start AutoSentry

```bash
# Start web server
python main.py server

# Alternative if main.py has issues
python run_server.py
```

### 4. Access Web Interface

Open: **http://localhost:5000**

## 💻 Usage Examples

### Web Interface
1. Go to http://localhost:5000
2. Enter target URL (e.g., `https://example.com`)
3. Select scan type (Basic/Nmap/Nikto/Full)
4. Click "Start Scan" and view results

### Command Line
```bash
# Health check
python main.py client health

# Basic web scan
python main.py client scan https://example.com --type basic

# Full assessment with detailed results
python main.py client scan https://example.com --type full --detailed

# Check scanner status
python main.py client status
```

### Python Function (Main Feature)
```python
from scanner_function import scan_url

# Basic scan
results = scan_url('https://example.com')
print(f"Found {results['summary']['total_vulnerabilities']} vulnerabilities")

# Full scan with CSV export
csv_results = scan_url('https://example.com', 'full', 'csv')
with open('results.csv', 'w') as f:
    f.write(csv_results)

# Get vulnerability list
vulns = scan_url('https://example.com', 'basic', 'list')
for vuln in vulns:
    print(f"{vuln['name']} - {vuln['risk_level']}")
```

## 🔍 Scan Types

- **Basic**: Fast web security check (security headers, server info, cookies)
- **Nmap**: Network scan (open ports, services, OS detection)  
- **Nikto**: Web vulnerability scan (6700+ vulnerability checks)
- **Full**: Combined scan using all available scanners

## 🛡️ Vulnerability Detection

### Web Application Security
- Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
- Server information disclosure
- Insecure cookie configurations
- Dangerous HTTP methods

### Network Security
- Open ports and services
- Service version detection
- Potentially insecure services (FTP, Telnet, RDP)
- Network service enumeration

### Web Server Vulnerabilities
- 6700+ known vulnerability checks (Nikto)
- Dangerous files and directories
- Server-specific vulnerabilities
- Configuration issues

## 📊 Risk Assessment

- **🔴 High Risk**: Critical vulnerabilities requiring immediate attention
- **🟡 Medium Risk**: Important security issues to address  
- **🟢 Low Risk**: Minor security improvements
- **ℹ️ Info**: Informational findings for awareness

## 🔧 Troubleshooting

### "Module not found" errors
```bash
pip install Flask Flask-CORS requests python-dotenv
```

### "Scanner not found" errors  
```bash
# Ubuntu/Debian
sudo apt install nmap nikto

# macOS
brew install nmap nikto
```

### Main server issues
```bash
# Use backup server
python run_server.py
```

### Port already in use
Edit `config/.env`:
```bash
AUTOSENTRY_PORT=5001
```

## 📁 Project Structure

```
autosentry_final/
├── main.py              # 🚀 Main entry point
├── run_server.py        # 🔄 Backup server runner
├── scanner_function.py  # 🎯 Main scanner function
├── README.md           # 📖 This file
├── server/
│   ├── app.py          # 🌐 Web application
│   ├── vapt_scanner.py # 🔍 Scanner orchestrator
│   ├── config.py       # ⚙️ Configuration
│   └── utils.py        # 🛠️ Utilities
├── client/
│   └── client.py       # 💻 CLI interface
└── config/
    ├── .env            # 🔧 Configuration
    └── requirements.txt # 📦 Dependencies
```

## 🎯 Perfect for Internship Demos

**Unique Features to Highlight:**
- ✅ Local-first architecture (no API costs)
- ✅ Professional enterprise-quality interface
- ✅ Multi-scanner integration in single platform
- ✅ Real-time vulnerability detection
- ✅ Multiple output formats (JSON, CSV, Web)
- ✅ Command-line + Web interfaces
- ✅ Python function for easy integration

## 🎪 Demo Script

*"I built AutoSentry, a comprehensive VAPT tool that integrates multiple security scanners into a unified platform. It runs entirely locally, features professional web dashboard, and can detect various security vulnerabilities including missing headers, open ports, and web server issues. The tool supports multiple interfaces - web, command-line, and Python function integration."*

## 📄 License

MIT License - Feel free to use for educational and professional purposes.

---

**🛡️ AutoSentry - Professional Vulnerability Assessment Made Simple**

For issues or questions, check the troubleshooting section above or run `python main.py setup` to diagnose problems.
