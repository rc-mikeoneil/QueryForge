#!/usr/bin/env python3
"""Debug entrypoint for ECS container troubleshooting."""

import os
import sys
import subprocess
import traceback
from pathlib import Path

def run_command(cmd):
    """Run a command and return its output."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout + result.stderr
    except Exception as e:
        return f"Error running command: {e}"

def main():
    print("=== Starting Debug Entrypoint (Python) ===", flush=True)
    
    # User information
    print(f"Current user: {os.environ.get('USER', 'unknown')}", flush=True)
    print(f"User ID: {os.getuid()}", flush=True)
    print(f"Group ID: {os.getgid()}", flush=True)
    print(f"Working directory: {os.getcwd()}", flush=True)
    
    # Directory contents
    print("\n=== Contents of working directory ===", flush=True)
    for item in sorted(os.listdir('.')):
        path = Path(item)
        if path.is_dir():
            print(f"  [DIR]  {item}/", flush=True)
        else:
            print(f"  [FILE] {item}", flush=True)
    
    # Environment variables
    print("\n=== Environment Variables ===", flush=True)
    for key, value in sorted(os.environ.items()):
        if any(x in key for x in ['MCP_', 'CACHE_', 'LITELLM_', 'PATH', 'PYTHON']):
            # Mask sensitive values
            if 'KEY' in key or 'SECRET' in key:
                value = value[:10] + '...' if len(value) > 10 else '***'
            print(f"  {key}={value}", flush=True)
    
    # Cache directory check
    print("\n=== Cache Directory Check ===", flush=True)
    cache_dir = os.environ.get('CACHE_DIR', '/app/.cache')
    print(f"CACHE_DIR is: {cache_dir}", flush=True)
    if os.path.exists(cache_dir):
        print(f"Cache directory exists: {cache_dir}", flush=True)
        try:
            test_file = os.path.join(cache_dir, '.test_write')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            print("Cache directory is writable", flush=True)
        except Exception as e:
            print(f"Cache directory is NOT writable: {e}", flush=True)
    else:
        print(f"Cache directory does NOT exist: {cache_dir}", flush=True)
        try:
            os.makedirs(cache_dir, exist_ok=True)
            print(f"Created cache directory: {cache_dir}", flush=True)
        except Exception as e:
            print(f"Failed to create cache directory: {e}", flush=True)
    
    # Python check
    print("\n=== Python Check ===", flush=True)
    print(f"Python executable: {sys.executable}", flush=True)
    print(f"Python version: {sys.version}", flush=True)
    print(f"Python path: {sys.path}", flush=True)
    
    # Module import test
    print("\n=== Python Import Test ===", flush=True)
    
    try:
        import fastmcp
        print(f"FastMCP import: SUCCESS (version: {getattr(fastmcp, '__version__', 'unknown')})", flush=True)
    except Exception as e:
        print(f"FastMCP import: FAILED - {e}", flush=True)
        traceback.print_exc()
    
    try:
        from queryforge.server import server
        print("Server import: SUCCESS", flush=True)
    except Exception as e:
        print(f"Server import: FAILED - {e}", flush=True)
        traceback.print_exc()
    
    # Network check
    print("\n=== Network Check ===", flush=True)
    hostname = run_command("hostname -f")
    print(f"Hostname: {hostname.strip()}", flush=True)
    
    # Start the server
    print("\n=== Attempting to start server ===", flush=True)
    print(f"Running: python -m queryforge.server.server", flush=True)
    sys.stdout.flush()
    sys.stderr.flush()
    
    # Replace this process with the server
    os.execvp(sys.executable, [sys.executable, '-m', 'queryforge.server.server'])

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"\n=== FATAL ERROR ===", flush=True)
        print(f"Error: {e}", flush=True)
        traceback.print_exc()
        sys.exit(1)
