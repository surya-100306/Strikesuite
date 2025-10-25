@echo off
REM StrikeSuite CLI Launcher Script for Windows

REM Get the directory where this script is located
set SCRIPT_DIR=%~dp0

REM Change to the StrikeSuite directory
cd /d "%SCRIPT_DIR%"

REM Run the CLI
python strikesuite_cli.py %*

