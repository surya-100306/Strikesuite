@echo off
REM StrikeSuite v1.0 - Simple Run Script

echo StrikeSuite v1.0 - Advanced Penetration Testing Toolkit
echo ======================================================
echo.

REM Activate virtual environment
call strikesuite_env\Scripts\activate.bat

echo Choose an option:
echo 1. Test installation
echo 2. Run example scan (localhost)
echo 3. Run custom scan
echo 4. Show help
echo.

set /p choice="Enter your choice (1-4): "

if "%choice%"=="1" (
    echo Testing installation...
    python strikesuite_cli.py --test
) else if "%choice%"=="2" (
    echo Running example scan on localhost...
    python strikesuite_cli.py --target 127.0.0.1 --ports 22,80,443,8080 --scan-type port
) else if "%choice%"=="3" (
    echo.
    set /p target="Enter target IP/hostname: "
    set /p ports="Enter ports (comma-separated, e.g., 22,80,443): "
    echo Running scan on %target%...
    python strikesuite_cli.py --target %target% --ports %ports% --scan-type all
) else if "%choice%"=="4" (
    python strikesuite_cli.py --help
) else (
    echo Invalid choice. Showing help...
    python strikesuite_cli.py --help
)

echo.
pause
