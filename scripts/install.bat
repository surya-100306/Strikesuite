@echo off
REM StrikeSuite v1.0 Installation Script for Windows

echo StrikeSuite v1.0 - Advanced Penetration Testing Toolkit
echo ======================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

echo ✓ Python installation found

REM Create virtual environment
echo Creating virtual environment...
python -m venv strikesuite_env

REM Activate virtual environment
echo Activating virtual environment...
call strikesuite_env\Scripts\activate.bat

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt

REM Create necessary directories
echo Creating directory structure...
if not exist "logs\scan_logs" mkdir logs\scan_logs
if not exist "logs\api_logs" mkdir logs\api_logs
if not exist "logs\error_logs" mkdir logs\error_logs
if not exist "reports\generated" mkdir reports\generated
if not exist "database" mkdir database

REM Set up database
echo Initializing database...
python -c "from utils.db_utils import init_db; init_db()" 2>nul || echo Database initialization failed - will be created on first run

echo.
echo Installation completed!
echo.
echo To run StrikeSuite:
echo 1. Activate the virtual environment: strikesuite_env\Scripts\activate.bat
echo 2. Run the application: python strikesuite_cli.py
echo.
echo For more information, see the documentation in the docs\ directory.
pause
