#!/bin/bash
# StrikeSuite v1.0 Installation Script for Linux/Mac

echo "StrikeSuite v1.0 - Advanced Penetration Testing Toolkit"
echo "======================================================"
echo

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    echo "Please install Python 3.8+ from https://python.org"
    exit 1
fi

echo "✓ Python installation found"

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv strikesuite_env

# Activate virtual environment
echo "Activating virtual environment..."
source strikesuite_env/bin/activate

# Upgrade pip
echo "Upgrading pip..."
python -m pip install --upgrade pip

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Create necessary directories
echo "Creating directory structure..."
mkdir -p logs/scan_logs
mkdir -p logs/api_logs
mkdir -p logs/error_logs
mkdir -p reports/generated
mkdir -p database
mkdir -p assets/icons/tab_icons
mkdir -p assets/images
mkdir -p assets/sounds
mkdir -p docs/screenshots

# Set up database
echo "Initializing database..."
python -c "from utils.db_utils import init_db; init_db()" 2>/dev/null || echo "Database initialization failed - will be created on first run"

echo
echo "Installation completed!"
echo
echo "To run StrikeSuite:"
echo "1. Activate the virtual environment: source strikesuite_env/bin/activate"
echo "2. Run the application: python strikesuite.py"
echo
echo "For more information, see the documentation in the docs/ directory."
