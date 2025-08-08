#!/usr/bin/env python3
"""
AutoSentry Backup Server Runner
Use this if main.py server has any issues
"""

import sys
import os

# Get script directory and add to path
script_dir = os.path.dirname(os.path.abspath(__file__))
server_dir = os.path.join(script_dir, 'server')
sys.path.insert(0, script_dir)
sys.path.insert(0, server_dir)

try:
    print("🛡️  AutoSentry Backup Server Starting...")
    print("📍 Loading server components...")

    from server.app import app

    print("✅ Server components loaded successfully")
    print("📍 Server URL: http://localhost:5000")
    print("🌐 Web Dashboard: http://localhost:5000")
    print("⏹️  Press Ctrl+C to stop")
    print("")

    # Run server in production mode (no debug, no reloader)
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        use_reloader=False,
        threaded=True
    )

except ImportError as e:
    print(f"❌ Import error: {e}")
    print("\n🔧 Troubleshooting:")
    print("1. Make sure you're in the correct directory")
    print("2. Install dependencies:")
    print("   pip install Flask Flask-CORS requests python-dotenv")
    print("3. Check if server/app.py exists")
except KeyboardInterrupt:
    print("\n👋 Server stopped by user")
except Exception as e:
    print(f"❌ Server error: {e}")
    import traceback
    traceback.print_exc()
