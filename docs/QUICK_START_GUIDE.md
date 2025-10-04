# StrikeSuite Quick Start Guide

## 🚀 Getting Started in 5 Minutes

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/strikesuite.git
cd strikesuite

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Test Installation

```bash
# Test CLI
python strikesuite_cli.py --test

# Test GUI
python strikesuite.py
```

### 3. Basic Usage

#### GUI Mode
```bash
python strikesuite.py
```
1. Enter target IP/hostname
2. Select scan type
3. Click "Start Scan"
4. Review results

#### CLI Mode
```bash
# Basic port scan
python strikesuite_cli.py --target 192.168.1.1

# Advanced scan
python strikesuite_cli.py --target 192.168.1.1 --advanced --stealth
```

### 4. Common Commands

```bash
# Network scan
python strikesuite_cli.py --target 192.168.1.1 --scan-type port --ports 22,80,443

# Vulnerability scan
python strikesuite_cli.py --target 192.168.1.1 --scan-type vuln --advanced

# API testing
python strikesuite_cli.py --target https://api.example.com --scan-type api --fuzzing

# Generate report
python strikesuite_cli.py --target 192.168.1.1 --output report.pdf --format pdf
```

### 5. First Scan Example

```bash
# Scan localhost (safe for testing)
python strikesuite_cli.py --target 127.0.0.1 --scan-type all --advanced
```

## 📋 Quick Reference

### GUI Tabs
- **Network**: Port scanning and service detection
- **API**: API security testing
- **Vulnerability**: Vulnerability assessment
- **Brute Force**: Password attacks
- **Exploitation**: Safe exploit testing
- **Post-Exploitation**: System analysis
- **Plugins**: Custom tools
- **Reporting**: Generate reports

### CLI Options
- `--target`: Target to scan
- `--scan-type`: Type of scan (port, vuln, api, all)
- `--advanced`: Enable advanced features
- `--stealth`: Enable stealth mode
- `--output`: Output file
- `--format`: Output format (json, pdf, html)

### Advanced Features
- `--os-detection`: OS fingerprinting
- `--service-detection`: Service detection
- `--fuzzing`: API fuzzing
- `--jwt-analysis`: JWT security analysis
- `--brute-force`: Brute force attacks
- `--exploitation`: Exploit testing

## ⚠️ Important Notes

1. **Always get permission** before testing
2. **Use stealth mode** for sensitive environments
3. **Start with basic scans** before advanced techniques
4. **Review results carefully** for accuracy
5. **Generate reports** for documentation

## 🆘 Need Help?

- Check the main project book: `StrikeSuite_Project_Book.md`
- Review troubleshooting section
- Check GitHub issues
- Contact support

---

*Happy Testing! 🛡️*


