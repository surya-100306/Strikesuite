@echo off
REM StrikeSuite v1.0 Run Script

echo Starting StrikeSuite v1.0...
echo.

REM Activate virtual environment
call strikesuite_env\Scripts\activate.bat

REM Test installation first
echo Testing installation...
python test_installation.py

echo.
echo Choose an option:
echo 1. Run GUI version (requires PyQt5)
echo 2. Run CLI version
echo 3. Install PyQt5 for GUI
echo.

set /p choice="Enter your choice (1-3): "

if "%choice%"=="1" (
    echo Running GUI version...
    python strikesuite.py
) else if "%choice%"=="2" (
    echo Running CLI version...
    echo.
    echo Example usage:
    echo python strikesuite_cli.py --target 192.168.1.1 --ports 22,80,443
    echo.
    python strikesuite_cli.py --help
) else if "%choice%"=="3" (
    echo Installing PyQt5...
    pip install PyQt5
    echo PyQt5 installed. You can now run the GUI version.
    pause
) else (
    echo Invalid choice. Running CLI version...
    python strikesuite_cli.py --help
)

pause
