#!/usr/bin/env python3
"""
AutoSentry - VAPT Tool
Main entry point for the application

Usage:
    python main.py server    # Start the server
    python main.py client    # Run client commands  
    python main.py setup     # Run setup checks
"""

import sys
import os
import argparse

def start_server():
    """Start the AutoSentry server"""
    try:
        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        server_dir = os.path.join(script_dir, 'server')

        # Add both directories to Python path
        sys.path.insert(0, script_dir)
        sys.path.insert(0, server_dir)

        # Import the Flask app
        from server.app import app

        # Try to load configuration
        try:
            from server.config import config
            host = config.HOST
            port = config.PORT
            debug = False  # Always False to prevent restart issues
        except:
            # Fallback configuration
            host = os.getenv('AUTOSENTRY_HOST', '0.0.0.0')
            port = int(os.getenv('AUTOSENTRY_PORT', '5000'))
            debug = False

        print("🛡️  Starting AutoSentry VAPT Tool Server...")
        print(f"📍 Server URL: http://{host}:{port}")
        print("⏹️  Press Ctrl+C to stop")
        print("")

        # Start server without debug mode to avoid restart issues
        app.run(
            host=host,
            port=port,
            debug=debug,
            use_reloader=False,  # Disable auto-reloader
            threaded=True        # Enable threading for better performance
        )

    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("\n🔧 Troubleshooting:")
        print("1. Make sure you're in the autosentry_final directory")
        print("2. Install dependencies: pip install Flask Flask-CORS requests python-dotenv")
        print("3. Try the backup server: python run_server.py")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Server startup error: {e}")
        sys.exit(1)

def run_client():
    """Run the client application"""
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        client_dir = os.path.join(script_dir, 'client')

        sys.path.insert(0, script_dir)
        sys.path.insert(0, client_dir)

        from client.client import main
        main()

    except ImportError as e:
        print(f"❌ Client import error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Client error: {e}")
        sys.exit(1)

def run_setup():
    """Run setup checks"""
    print("🛡️  AutoSentry Setup Check")
    print("=" * 30)

    # Check Python version
    python_version = sys.version_info
    print(f"Python Version: {python_version.major}.{python_version.minor}.{python_version.micro}")

    if python_version < (3, 6):
        print("❌ Python 3.6+ is required")
        return False
    else:
        print("✅ Python version OK")

    # Check required packages
    required_packages = [
        ('flask', 'Flask'),
        ('flask_cors', 'Flask-CORS'),
        ('requests', 'requests'),
        ('dotenv', 'python-dotenv'),
    ]

    missing_packages = []
    for package, pip_name in required_packages:
        try:
            __import__(package)
            print(f"✅ {pip_name}")
        except ImportError:
            print(f"❌ {pip_name} - Missing")
            missing_packages.append(pip_name)

    if missing_packages:
        print(f"\n📦 Install missing packages:")
        print(f"pip install {' '.join(missing_packages)}")
        return False

    # Check system tools
    import subprocess

    tools = [
        ('nmap', 'Nmap network scanner', ['nmap', '--version']),
        ('nikto', 'Nikto web vulnerability scanner', ['nikto', '-Version']),
        ('java', 'Java (for ZAP)', ['java', '-version'])
    ]

    print(f"\n🔍 System Tools:")
    for tool, description, cmd in tools:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"✅ {tool} - Available")
            else:
                print(f"⚠️  {tool} - Available but may have issues")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print(f"❌ {tool} - Not found ({description})")

    # Check configuration
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, 'config', '.env')
    if os.path.exists(config_path):
        print(f"✅ Configuration file found: {config_path}")
    else:
        print(f"⚠️  Configuration file not found: {config_path}")
        print("   Creating default configuration...")
        try:
            # Create basic config if missing
            os.makedirs(os.path.join(script_dir, 'config'), exist_ok=True)
            with open(config_path, 'w') as f:
                f.write("""AUTOSENTRY_HOST=0.0.0.0
AUTOSENTRY_PORT=5000
AUTOSENTRY_DEBUG=False
ENABLE_NMAP=True
ENABLE_NIKTO=True
RESULTS_DIR=./results
TEMP_DIR=./temp
LOGS_DIR=./logs
""")
            print(f"✅ Created basic configuration: {config_path}")
        except Exception as e:
            print(f"❌ Could not create config: {e}")

    # Check directories
    directories = ['results', 'logs', 'temp']
    for directory in directories:
        dir_path = os.path.join(script_dir, directory)
        if os.path.exists(dir_path):
            print(f"✅ Directory exists: {directory}/")
        else:
            try:
                os.makedirs(dir_path, exist_ok=True)
                print(f"✅ Created directory: {directory}/")
            except Exception as e:
                print(f"❌ Cannot create directory {directory}/: {e}")

    print("\n🎉 Setup check complete!")
    print("\n🚀 To start AutoSentry:")
    print("   python main.py server")
    print("\n🔄 If main.py has issues, use:")
    print("   python run_server.py")

    return True

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="AutoSentry VAPT Tool")
    parser.add_argument('mode', 
                       choices=['server', 'client', 'setup'],
                       help='Application mode')

    # If no arguments, show help
    if len(sys.argv) == 1:
        parser.print_help()
        print("\n🛡️  AutoSentry VAPT Tool")
        print("Examples:")
        print("  python main.py server   # Start web server")
        print("  python main.py client scan https://example.com")
        print("  python main.py setup    # Check setup")
        sys.exit(1)

    args = parser.parse_args()

    try:
        if args.mode == 'server':
            start_server()
        elif args.mode == 'client':
            # Remove 'client' from sys.argv so client can parse its own args
            sys.argv = [sys.argv[0]] + sys.argv[2:]
            run_client()
        elif args.mode == 'setup':
            success = run_setup()
            sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
