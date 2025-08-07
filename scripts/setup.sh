#!/bin/bash

# AutoSentry VAPT Tool Setup Script
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
    exit 1
fi

# Install Python dependencies
echo "📦 Installing Python dependencies..."
if pip3 install -r config/requirements.txt; then
    echo_success "Python dependencies installed"
else
    echo_error "Failed to install Python dependencies"
    exit 1
fi

# Check for system tools
echo "🔍 Checking system tools..."

# Check Nmap
if command -v nmap >/dev/null 2>&1; then
    echo_success "Nmap is installed"
else
    echo_warning "Nmap not found - installing..."

    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y nmap
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y nmap
    elif command -v brew >/dev/null 2>&1; then
        brew install nmap
    else
        echo_error "Please install Nmap manually"
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
    elif command -v brew >/dev/null 2>&1; then
        brew install nikto
    else
        echo_error "Please install Nikto manually"
    fi
fi

# Create directories
echo "📁 Creating directories..."
mkdir -p results logs temp
echo_success "Directories created"

# Setup configuration
if [ ! -f "config/.env" ]; then
    echo "⚙️  Setting up configuration..."
    cp config/.env.example config/.env
    echo_success "Configuration file created"
else
    echo_success "Configuration file already exists"
fi

# Run setup check
echo "🧪 Running setup verification..."
if python3 main.py setup; then
    echo_success "Setup verification passed"
else
    echo_warning "Some setup checks failed - but AutoSentry should still work"
fi

echo ""
echo "🎉 AutoSentry setup complete!"
echo "=============================="
echo ""
echo "🚀 To start AutoSentry:"
echo "  python3 main.py server"
echo ""
echo "🌐 Then open: http://localhost:5000"
echo ""
echo "💻 For CLI usage:"
echo "  python3 main.py client --help"
echo ""
echo "Happy scanning! 🛡️"
