#!/usr/bin/env python3
"""
Cloud Security Automation Tool - Management CLI
"""

import os
import sys
import argparse
import subprocess
from pathlib import Path

def setup_environment():
    """Set up the project environment"""
    print("Setting up Cloud Security Automation Tool...")
    
    # Check if virtual environment exists
    venv_path = Path("venv")
    if not venv_path.exists():
        print("Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
    
    # Determine activation script path
    if os.name == 'nt':  # Windows
        activate_script = venv_path / "Scripts" / "activate.bat"
        pip_path = venv_path / "Scripts" / "pip"
    else:  # Unix/Linux/macOS
        activate_script = venv_path / "bin" / "activate"
        pip_path = venv_path / "bin" / "pip"
    
    # Install dependencies
    print("Installing dependencies...")
    subprocess.run([str(pip_path), "install", "-r", "requirements.txt"], check=True)
    
    # Check if .env file exists
    env_file = Path(".env")
    if not env_file.exists():
        print("Creating .env file from template...")
        subprocess.run(["cp", ".env.example", ".env"], check=True)
        print("Please edit .env file with your AWS credentials and configuration")
    
    print("Setup completed successfully!")
    print(f"To activate the virtual environment, run:")
    if os.name == 'nt':
        print(f"  {activate_script}")
    else:
        print(f"  source {activate_script}")

def run_server():
    """Start the Flask development server"""
    print("Starting Cloud Security Automation Tool...")
    
    # Check if virtual environment exists
    venv_path = Path("venv")
    if not venv_path.exists():
        print("Virtual environment not found. Run 'python manage.py setup' first.")
        return
    
    # Determine Python path
    if os.name == 'nt':  # Windows
        python_path = venv_path / "Scripts" / "python"
    else:  # Unix/Linux/macOS
        python_path = venv_path / "bin" / "python"
    
    # Change to src directory and run the application
    os.chdir("src")
    subprocess.run([str(python_path), "main.py"])

def run_scan():
    """Run a security scan via CLI"""
    print("Starting security scan...")
    
    # This would typically make an API call to trigger a scan
    # For now, we'll just show instructions
    print("To run a scan:")
    print("1. Start the server with: python manage.py run")
    print("2. Open http://localhost:5000 in your browser")
    print("3. Click 'Start Security Scan' button")
    print("Or use the API: POST http://localhost:5000/api/security/scan/start")

def show_status():
    """Show application status"""
    print("Cloud Security Automation Tool Status")
    print("=" * 40)
    
    # Check virtual environment
    venv_path = Path("venv")
    print(f"Virtual Environment: {'✓' if venv_path.exists() else '✗'}")
    
    # Check .env file
    env_file = Path(".env")
    print(f"Configuration File: {'✓' if env_file.exists() else '✗'}")
    
    # Check database
    db_file = Path("src/database/app.db")
    print(f"Database: {'✓' if db_file.exists() else '✗'}")
    
    # Check dependencies
    requirements_file = Path("requirements.txt")
    print(f"Requirements File: {'✓' if requirements_file.exists() else '✗'}")
    
    print("\nTo get started:")
    print("1. Run 'python manage.py setup' to initialize the environment")
    print("2. Edit .env file with your AWS credentials")
    print("3. Run 'python manage.py run' to start the server")

def main():
    parser = argparse.ArgumentParser(
        description="Cloud Security Automation Tool Management CLI"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Setup command
    subparsers.add_parser('setup', help='Set up the project environment')
    
    # Run command
    subparsers.add_parser('run', help='Start the Flask development server')
    
    # Scan command
    subparsers.add_parser('scan', help='Run a security scan')
    
    # Status command
    subparsers.add_parser('status', help='Show application status')
    
    args = parser.parse_args()
    
    if args.command == 'setup':
        setup_environment()
    elif args.command == 'run':
        run_server()
    elif args.command == 'scan':
        run_scan()
    elif args.command == 'status':
        show_status()
    else:
        parser.print_help()

if __name__ == '__main__':
    main()

