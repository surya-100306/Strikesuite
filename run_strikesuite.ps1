# StrikeSuite v1.0 PowerShell Run Script

Write-Host "StrikeSuite v1.0 - Advanced Penetration Testing Toolkit" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Green

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& "strikesuite_env\Scripts\Activate.ps1"

# Test installation
Write-Host "Testing installation..." -ForegroundColor Yellow
python test_installation.py

Write-Host ""
Write-Host "Choose an option:" -ForegroundColor Cyan
Write-Host "1. Run GUI version (requires PyQt5)" -ForegroundColor White
Write-Host "2. Run CLI version" -ForegroundColor White
Write-Host "3. Install PyQt5 for GUI" -ForegroundColor White
Write-Host "4. Run example scan" -ForegroundColor White
Write-Host ""

$choice = Read-Host "Enter your choice (1-4)"

switch ($choice) {
    "1" {
        Write-Host "Running GUI version..." -ForegroundColor Green
        python strikesuite.py
    }
    "2" {
        Write-Host "Running CLI version..." -ForegroundColor Green
        Write-Host ""
        Write-Host "Example usage:" -ForegroundColor Yellow
        Write-Host "python strikesuite_cli.py --target 192.168.1.1 --ports 22,80,443" -ForegroundColor Gray
        Write-Host ""
        python strikesuite_cli.py --help
    }
    "3" {
        Write-Host "Installing PyQt5..." -ForegroundColor Yellow
        pip install PyQt5
        Write-Host "PyQt5 installed. You can now run the GUI version." -ForegroundColor Green
    }
    "4" {
        Write-Host "Running example scan on localhost..." -ForegroundColor Green
        python strikesuite_cli.py --target 127.0.0.1 --ports 22,80,443,8080 --scan-type port
    }
    default {
        Write-Host "Invalid choice. Running CLI help..." -ForegroundColor Red
        python strikesuite_cli.py --help
    }
}

Write-Host ""
Write-Host "Press any key to continue..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

