#!/bin/bash

# AutoSentry VAPT Tool Setup Script (Fixed Version)
echo "🛡️  AutoSentry VAPT Tool Setup"
echo "==============================="

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo_success() { echo -e "${GREEN}✅ $1${NC}"; }
echo_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
echo_error() { echo -e "${RED}❌ $1${NC}"; }

# Check Python version
python3 --version > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo_success "Python 3 is installed"
else
    echo_error "Python 3 is required but not installed"
    echo "Install Python 3 and try again"
    exit 1
fi

# Install core Python dependencies (minimal set)
echo "📦 Installing Python dependencies..."
echo "Installing core packages: Flask Flask-CORS requests python-dotenv"

if pip3 install Flask Flask-CORS requests python-dotenv; then
    echo_success "Core dependencies installed successfully"
else
    echo_error "Failed to install some dependencies"
    echo "Try: pip3 install --user Flask Flask-CORS requests python-dotenv"
fi

# Check for optional dependencies
echo "📦 Checking optional dependencies..."
pip3 install validators psutil 2>/dev/null && echo_success "Optional packages installed"

# Check for system tools
echo "🔍 Checking system tools..."

# Check Nmap
if command -v nmap >/dev/null 2>&1; then
    echo_success "Nmap is installed"
else
    echo_warning "Nmap not found - installing..."

    if command -v apt-get >/dev/null 2>&1; then
        echo "Using apt-get..."
        sudo apt-get update && sudo apt-get install -y nmap
    elif command -v yum >/dev/null 2>&1; then
        echo "Using yum..."
        sudo yum install -y nmap
    elif command -v dnf >/dev/null 2>&1; then
        echo "Using dnf..."
        sudo dnf install -y nmap
    elif command -v brew >/dev/null 2>&1; then
        echo "Using brew..."
        brew install nmap
    else
        echo_warning "Please install Nmap manually for full functionality"
    fi
fi

# Check Nikto
if command -v nikto >/dev/null 2>&1; then
    echo_success "Nikto is installed"
else
    echo_warning "Nikto not found - installing..."

    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get install -y nikto
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y nikto  
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y nikto
    elif command -v brew >/dev/null 2>&1; then
        brew install nikto
    else
        echo_warning "Please install Nikto manually for full functionality"
    fi
fi

# Create directories
echo "📁 Creating directories..."
mkdir -p results logs temp
echo_success "Directories created"

# Setup configuration (config file already exists)
if [ -f "config/.env" ]; then
    echo_success "Configuration file exists"
else
    echo_warning "Configuration file not found - creating default"
    mkdir -p config
    cat > config/.env << 'EOF'
AUTOSENTRY_HOST=0.0.0.0
AUTOSENTRY_PORT=5000
AUTOSENTRY_DEBUG=False
ENABLE_NMAP=True
ENABLE_NIKTO=True
MAX_SCAN_TIME=1800
RESULTS_DIR=./results
TEMP_DIR=./temp
LOGS_DIR=./logs
AUTOSENTRY_LOG_LEVEL=INFO
EOF
    echo_success "Default configuration created"
fi

# Run setup verification  
echo "🧪 Running setup verification..."
if python3 main.py setup; then
    echo_success "Setup verification passed"
else
    echo_warning "Some setup checks failed - but basic functionality should work"
fi

echo ""
echo "🎉 AutoSentry setup complete!"
echo "=============================="
echo ""
echo "🚀 To start AutoSentry:"
echo "   python3 main.py server"
echo ""
echo "🔄 If main.py has issues:"
echo "   python3 run_server.py"
echo ""
echo "🌐 Web interface:"
echo "   http://localhost:5000"
echo ""
echo "💻 CLI usage:"
echo "   python3 main.py client scan https://example.com"
echo ""
echo "🎯 Main scanner function:"
echo "   python3 scanner_function.py https://example.com --type basic"
echo ""
echo "Happy scanning! 🛡️"
