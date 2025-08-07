# 🛡️ AutoSentry VAPT Tool - Complete Setup Guide

## 📋 Step-by-Step Setup Instructions

Follow these exact commands to get AutoSentry working perfectly:

### Step 1: Extract and Navigate

```bash
# Extract the zip file
unzip autosentry_fixed.zip
cd autosentry_fixed
```

### Step 2: Install Python Dependencies

```bash
# Install required packages
pip install Flask Flask-CORS requests python-dotenv validators
```

### Step 3: Install System Scanners (Optional but Recommended)

#### Ubuntu/Debian:
```bash
sudo apt update
sudo apt install nmap nikto
```

#### CentOS/RHEL/Fedora:
```bash
# CentOS/RHEL
sudo yum install nmap nikto

# Fedora  
sudo dnf install nmap nikto
```

#### macOS:
```bash
brew install nmap nikto
```

### Step 4: Verify Setup

```bash
# Run setup check
python main.py setup
```

You should see:
- ✅ Python version OK
- ✅ Flask, requests, etc.
- ✅ nmap, nikto (if installed)
- ✅ Configuration file found

### Step 5: Start AutoSentry

```bash
# Start the server
python main.py server
```

You should see:
```
🛡️  Starting AutoSentry VAPT Tool Server...
Server URL: http://0.0.0.0:5000
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
```

### Step 6: Access Web Interface

Open your browser to: **http://localhost:5000**

You should see the AutoSentry dashboard with a professional interface.

### Step 7: Test Your First Scan

1. In the web interface:
   - Enter URL: `https://httpbin.org`
   - Select scan type: `Basic Web Security Check`
   - Click `🚀 Start Scan`

2. Or via command line:
```bash
python main.py client scan https://httpbin.org --type basic
```

## 🎯 Using the Main Scanner Function (As Requested)

The core scanner function you requested is in `scanner_function.py`:

```python
from scanner_function import scan_url

# Basic usage - returns JSON
results = scan_url('https://example.com')
print(f"Found {results['summary']['total_vulnerabilities']} vulnerabilities")

# Get results as CSV
csv_results = scan_url('https://example.com', 'basic', 'csv')
with open('results.csv', 'w') as f:
    f.write(csv_results)

# Get just the vulnerabilities list
vulns = scan_url('https://example.com', 'full', 'list')
for vuln in vulns:
    print(f"{vuln['name']} - {vuln['risk_level']}")
```

## 🚀 Quick Commands Reference

```bash
# Start server
python main.py server

# CLI scan
python main.py client scan https://example.com --type basic

# Check health
python main.py client health

# Check scanner status  
python main.py client status

# Use scanner function directly
python scanner_function.py https://example.com --type full --format csv
```

## 🔧 Troubleshooting

### Issue: "Module not found"
**Solution:**
```bash
pip install Flask Flask-CORS requests python-dotenv validators
```

### Issue: "Scanner not found"
**Solution:**
```bash
# Install system scanners
sudo apt install nmap nikto  # Ubuntu/Debian
brew install nmap nikto      # macOS
```

### Issue: "Port already in use"
**Solution:** Edit `config/.env` and change:
```bash
AUTOSENTRY_PORT=5001
```

### Issue: Permission errors
**Solution:** Don't run as root, ensure proper permissions:
```bash
chmod +x main.py
chmod +x scripts/setup.sh
```

## 🎪 Demo Features

Your AutoSentry tool now includes:

### ✅ Web Dashboard
- Professional UI at http://localhost:5000
- Real-time scanning results
- Risk-level categorization
- Multiple scan types

### ✅ Command Line Interface
- Full CLI client with help system
- Batch scanning capabilities
- JSON and CSV output formats

### ✅ Python Function (Main Request)
- `scan_url()` function as requested
- Multiple return formats (JSON, CSV, list)
- Easy integration with other projects

### ✅ Multi-Scanner Integration
- Basic web security scanner (always works)
- Nmap integration (if installed)
- Nikto integration (if installed)

### ✅ Professional Features
- Comprehensive vulnerability database
- Risk assessment and categorization
- Detailed reporting capabilities
- API endpoints for automation

## 🎉 Success Indicators

When everything is working correctly, you should see:

1. **Setup Check**: All ✅ green checkmarks
2. **Web Interface**: Professional dashboard loads at localhost:5000
3. **Scan Results**: Actual vulnerability findings displayed
4. **API Responses**: JSON data returned from /health endpoint
5. **CLI Commands**: All client commands work without errors

## 📝 Project Structure Summary

```
autosentry_fixed/
├── main.py              # 🚀 Start here - main entry point
├── scanner_function.py  # 🎯 Your requested scanner function
├── server/
│   ├── app.py          # 🌐 Web server and dashboard
│   ├── vapt_scanner.py # 🔍 Multi-scanner orchestrator  
│   ├── config.py       # ⚙️  Configuration management
│   └── utils.py        # 🛠️  Utility functions
├── client/
│   └── client.py       # 💻 Command-line interface
├── config/
│   ├── .env            # 🔧 Your settings (ready to use)
│   └── requirements.txt # 📦 Python dependencies
└── docs/
    └── README.md       # 📖 Complete documentation
```

**Everything is now properly structured and all the fixes from our troubleshooting session have been applied!** 🎉

This is a complete, working VAPT tool perfect for your internship demonstration.
