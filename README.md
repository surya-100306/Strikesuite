# 🛡️ StrikeSuite: Advanced Cybersecurity Testing Framework

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/yourusername/strikesuite)
[![Security](https://img.shields.io/badge/security-advanced-red.svg)](https://github.com/yourusername/strikesuite)

> **A comprehensive, advanced cybersecurity testing framework for penetration testers, security researchers, and cybersecurity professionals.**

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/strikesuite.git
cd strikesuite

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
# Option 1: Minimal installation (recommended)
pip install -r requirements-minimal.txt

# Option 2: Full installation (may have issues with some packages)
pip install -r requirements.txt

# Option 3: Install optional features separately
pip install -r requirements-optional.txt

# Test installation
python3 test_strikesuite.py

# Launch GUI
python strikesuite.py
```

## ✨ Features

### 🔍 **Advanced Network Scanning**
- Multiple scan types (TCP, SYN, UDP, Stealth)
- OS fingerprinting and service detection
- Vulnerability scanning integration
- Stealth mode operations
- AI-enhanced detection algorithms
- Behavioral pattern analysis
- Threat intelligence integration

### 🌐 **API Security Testing**
- OWASP API Top 10 coverage
- JWT security analysis
- Rate limiting and bypass testing
- Advanced fuzzing capabilities

### 🔐 **Vulnerability Assessment**
- Comprehensive vulnerability scanning
- SSL/TLS security analysis
- Web application security testing
- False positive reduction

### 💥 **Brute Force Attacks**
- Intelligent attack techniques
- Advanced password pattern generation
- Rate limit detection and bypass
- Service-specific credential patterns

### 🎯 **Exploitation Testing**
- Safe proof-of-concept demonstrations
- Advanced payload generation
- Evasion techniques
- Exploit chaining capabilities

### 🔍 **Post-Exploitation Analysis**
- Privilege escalation analysis
- Persistence mechanism detection
- Lateral movement analysis
- System enumeration

### 🔌 **Plugin System**
- Dynamic plugin loading
- Hot reloading capabilities
- Security sandboxing
- Performance monitoring

### 📊 **Comprehensive Reporting**
- Multiple output formats (PDF, HTML, JSON, XML)
- Executive summaries
- Technical details
- Vulnerability correlation

## 🖥️ Interface Options

### GUI Mode (Recommended)
```bash
python strikesuite.py
```
- Intuitive graphical interface
- Real-time progress monitoring
- Interactive result visualization
- Easy configuration management

### CLI Mode

**Multiple CLI Access Methods:**

```bash
# Method 1: Direct CLI script
python3 strikesuite_cli.py --help

# Method 2: Shell script (Linux/Mac)
./strikesuite-cli.sh --help

# Method 3: Batch file (Windows)
strikesuite-cli.bat --help

# Method 4: Module execution
python3 -m strikesuite.main --cli --help
```

**Basic Usage:**
```bash
# Basic network scan
python3 strikesuite_cli.py scan --target 192.168.1.1 --type network

# Port scan
python3 strikesuite_cli.py scan --target 192.168.1.1 --type ports --ports 22,80,443

# API testing
python3 strikesuite_cli.py test --target https://api.example.com --type api

# Vulnerability testing
python3 strikesuite_cli.py test --target https://example.com --type vulnerability

# Generate report
python3 strikesuite_cli.py report --output report.pdf --format PDF
```

## 📋 Usage Examples

### Network Security Assessment
```bash
# Network discovery scan
python3 strikesuite_cli.py scan --target 192.168.1.0/24 --type network

# Port scan with specific ports
python3 strikesuite_cli.py scan --target 192.168.1.1 --type ports --ports 22,80,443,8080

# Port scan with options
python3 strikesuite_cli.py scan --target 192.168.1.1 --type ports --ports 1-1000 --options "stealth,os-detection"
```

### Web Application Testing
```bash
# Vulnerability testing
python3 strikesuite_cli.py test --target https://example.com --type vulnerability

# API security testing
python3 strikesuite_cli.py test --target https://api.example.com --type api
```

### Report Generation
```bash
# Generate PDF report
python3 strikesuite_cli.py report --output security_report.pdf --format PDF --title "Security Assessment Report"

# Generate HTML report
python3 strikesuite_cli.py report --output report.html --format HTML --title "Network Scan Results"

# Generate JSON report
python3 strikesuite_cli.py report --output data.json --format JSON --title "Scan Data Export"
```

## 🏗️ Architecture

```
StrikeSuite Framework
├── 🔧 Core Modules
│   ├── Network Scanner
│   ├── Vulnerability Scanner
│   ├── API Tester
│   ├── Brute Forcer
│   ├── Exploit Module
│   └── Post-Exploitation
├── 🖥️ GUI Components
│   ├── Main Window
│   ├── Network Tab
│   ├── API Tab
│   ├── Vulnerability Tab
│   ├── Brute Force Tab
│   ├── Exploitation Tab
│   ├── Post-Exploitation Tab
│   └── Plugins Tab
├── 💻 CLI Interface
├── 🔌 Plugin System
├── 🗄️ Database Layer
└── 📊 Reporting Engine
```

## 📚 Documentation

- **[📖 Project Book](StrikeSuite_Project_Book.md)** - Comprehensive documentation
- **[🚀 Quick Start Guide](docs/QUICK_START_GUIDE.md)** - Get started in 5 minutes
- **[🔧 API Reference](docs/API_REFERENCE.md)** - Complete API documentation
- **[👨‍💻 Developer Guide](docs/DEVELOPER_GUIDE.md)** - Development and contribution guide

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- Windows 10/11 (primary platform)
- 4GB RAM minimum (8GB recommended)
- 2GB free disk space

### Installation Steps

1. **Clone Repository**
```bash
git clone https://github.com/yourusername/strikesuite.git
cd strikesuite
```

2. **Create Virtual Environment**
```bash
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac
```

3. **Install Dependencies**
```bash
pip install -r requirements.txt
```

4. **Initialize Database**
```bash
python -c "from utils.db_utils import init_db; init_db()"
```

5. **Test Installation**
```bash
python3 test_strikesuite.py
```

### GUI Installation
```bash
# Install GUI dependencies
pip install PyQt5

# Run GUI application
python strikesuite.py
```

## 🔧 Advanced Configuration

### CLI Options
```bash
# Advanced options
--advanced              # Enable advanced features
--stealth              # Enable stealth mode
--depth [quick|standard|deep|comprehensive]  # Scan depth
--threads N            # Number of threads
--timeout N            # Connection timeout

# Scan options
--os-detection         # OS fingerprinting
--service-detection    # Service detection
--vulnerability-scan   # Vulnerability scanning

# API testing
--fuzzing              # API fuzzing
--parameter-pollution  # Parameter pollution
--jwt-analysis         # JWT security analysis
--rate-limit-bypass    # Rate limit bypass

# Brute force
--brute-force          # Enable brute force
--wordlist FILE        # Custom wordlist
--username-list FILE   # Username list
--password-list FILE   # Password list

# Exploitation
--exploitation         # Enable exploitation
--payload-generation   # Advanced payload generation
--evasion-techniques   # Evasion techniques
--exploit-chaining     # Exploit chaining

# Post-exploitation
--post-exploitation    # Enable post-exploitation
--privilege-escalation # Privilege escalation analysis
--persistence-analysis # Persistence analysis
--lateral-movement     # Lateral movement analysis

# Output options
--output FILE          # Output file
--format [json|xml|csv|html|pdf]  # Output format
--verbose              # Verbose output
```

## 🧪 Testing

### Run Tests
```bash
# Run all tests
python test_advanced_integration.py

# Test specific components
python -c "from core.scanner import NetworkScanner; print('Scanner OK')"
python -c "from gui.main_window import MainWindow; print('GUI OK')"
```

### Test Installation
```bash
# Test all components
python3 test_strikesuite.py

# Test GUI
python3 strikesuite.py
```

## 🔧 Troubleshooting

### Installation Issues

**Problem**: `python-zmap` or `python-masscan` not found
```bash
# Solution: Use minimal requirements instead
pip install -r requirements-minimal.txt
```

**Problem**: `externally-managed-environment` error
```bash
# Solution: Use virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows
pip install -r requirements-minimal.txt
```

**Problem**: PyQt5 installation fails
```bash
# Solution: Install system dependencies first (Ubuntu/Debian)
sudo apt-get install python3-pyqt5 python3-pyqt5-dev
# Then install minimal requirements
pip install -r requirements-minimal.txt
```

**Problem**: nmap not working
```bash
# Solution: Install nmap system package
sudo apt-get install nmap  # Ubuntu/Debian
# or
sudo yum install nmap  # CentOS/RHEL
```

### Runtime Issues

**Problem**: "scapy not available" warnings
- This is normal - scapy is optional for advanced features
- Core functionality works without it

**Problem**: "ReportLab not available" warnings  
- This is normal - PDF generation is optional
- HTML reports still work

**Problem**: GUI won't start
```bash
# Test CLI mode instead
python3 strikesuite_cli.py --help
```

## 🔌 Plugin Development

### Create Plugin
```python
# plugins/my_plugin.py
class MyPlugin:
    def __init__(self):
        self.name = "My Plugin"
        self.version = "1.0"
        self.description = "Custom plugin for StrikeSuite"
    
    def execute(self, target, options):
        # Plugin implementation
        return {"result": "success"}
    
    def get_info(self):
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description
        }
```

### Register Plugin
```python
# plugins/__init__.py
from .my_plugin import MyPlugin

PLUGINS = [MyPlugin]
```

## 📊 Performance

### Optimization Tips
- Use stealth mode for sensitive environments
- Limit port ranges for faster scans
- Adjust thread count based on system resources
- Use advanced features selectively

### Resource Usage
- **Memory**: 100-500MB typical usage
- **CPU**: Multi-threaded operations
- **Network**: Configurable rate limiting
- **Storage**: SQLite database + reports

## 🔒 Security

### Safe Testing Practices
- Always get permission before testing
- Use stealth mode for sensitive environments
- Review results carefully for false positives
- Generate comprehensive reports for documentation

### Built-in Safeguards
- Safe exploitation testing environment
- Input validation and sanitization
- Rate limiting and timeout controls
- Error handling and recovery

## 🤝 Contributing

### How to Contribute
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Development Setup
```bash
# Clone your fork
git clone https://github.com/yourusername/strikesuite.git
cd strikesuite

# Create development environment
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# Install development tools
pip install pytest black flake8
```

### Code Style
- Follow PEP 8
- Add docstrings to all functions
- Write tests for new features
- Ensure safe testing practices

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **OWASP** for security testing guidelines
- **Python community** for excellent libraries
- **Security researchers** for vulnerability databases
- **Open source contributors** for inspiration

## 📞 Support

- **Documentation**: [Project Book](StrikeSuite_Project_Book.md)
- **Issues**: [GitHub Issues](https://github.com/yourusername/strikesuite/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/strikesuite/discussions)
- **Email**: contact@strikesuite.com

## 🗺️ Roadmap

### Version 1.1
- [ ] Enhanced plugin system
- [ ] Additional scan types
- [ ] Improved reporting
- [ ] Performance optimizations

### Version 1.2
- [ ] Machine learning integration
- [ ] Advanced evasion techniques
- [ ] Cloud platform support
- [ ] Mobile application testing

### Version 2.0
- [ ] Distributed scanning
- [ ] Real-time collaboration
- [ ] Advanced analytics
- [ ] Enterprise features

---

## ⚠️ Disclaimer

**This tool is for authorized security testing only. Always ensure you have proper permission before testing any system. The authors are not responsible for any misuse of this tool.**

---

<div align="center">

**🛡️ StrikeSuite - Advanced Cybersecurity Testing Framework**

*Built with ❤️ for the cybersecurity community*

[![GitHub stars](https://img.shields.io/github/stars/yourusername/strikesuite?style=social)](https://github.com/yourusername/strikesuite)
[![GitHub forks](https://img.shields.io/github/forks/yourusername/strikesuite?style=social)](https://github.com/yourusername/strikesuite)
[![GitHub watchers](https://img.shields.io/github/watchers/yourusername/strikesuite?style=social)](https://github.com/yourusername/strikesuite)

</div>