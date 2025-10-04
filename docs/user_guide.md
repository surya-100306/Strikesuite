# StrikeSuite User Guide

## Table of Contents
1. [Getting Started](#getting-started)
2. [Network Scanning](#network-scanning)
3. [API Security Testing](#api-security-testing)
4. [Vulnerability Assessment](#vulnerability-assessment)
5. [Exploitation Testing](#exploitation-testing)
6. [Brute Force Attacks](#brute-force-attacks)
7. [Post-Exploitation](#post-exploitation)
8. [Report Generation](#report-generation)
9. [Plugin System](#plugin-system)
10. [Configuration](#configuration)

## Getting Started

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/strikesuite/strikesuite.git
   cd strikesuite
   ```

2. **Run installation script:**
   ```bash
   # Linux/Mac
   chmod +x scripts/install.sh
   ./scripts/install.sh
   
   # Windows
   scripts\install.bat
   ```

3. **Launch StrikeSuite:**
   ```bash
   python strikesuite.py
   ```

### First Steps

1. **Configure Settings:** Go to Tools > Settings to configure your preferences
2. **Load Plugins:** Use the Plugins tab to load additional security modules
3. **Start Scanning:** Use the Network Scanner tab for your first scan

## Network Scanning

### Basic Network Scan

1. **Open Network Scanner tab**
2. **Enter target:** IP address, hostname, or URL
3. **Select scan type:**
   - Common Ports: Quick scan of common ports
   - Port Range: Custom port range (e.g., 1-1000)
   - Custom Ports: Specific ports (e.g., 22,80,443)
4. **Configure options:**
   - Threads: Number of concurrent connections
   - Timeout: Connection timeout
   - Service Detection: Enable/disable service detection
5. **Start scan**

### Advanced Scanning

- **Nmap Integration:** Use Nmap for advanced scanning
- **Service Detection:** Identify running services
- **Banner Grabbing:** Collect service banners
- **OS Detection:** Detect operating system

## API Security Testing

### OWASP API Top 10 Testing

1. **Open API Security tab**
2. **Configure API:**
   - Base URL: API endpoint
   - Authentication: Bearer token, API key, or Basic auth
3. **Select tests:**
   - API1: Broken Object Level Authorization
   - API2: Broken User Authentication
   - API3: Excessive Data Exposure
   - And more...
4. **Add endpoints:** List API endpoints to test
5. **Start testing**

### Authentication Testing

- **Bearer Token:** JWT token analysis
- **API Key:** Key validation testing
- **Basic Auth:** Credential testing
- **OAuth2:** OAuth flow testing

## Vulnerability Assessment

### SSL/TLS Analysis

- Certificate validation
- Cipher suite analysis
- Protocol version checking
- Security misconfigurations

### Web Application Scanning

- SQL injection testing
- Cross-site scripting (XSS)
- Local/Remote file inclusion
- Command injection
- XML external entity (XXE)
- Server-side request forgery (SSRF)

### Default Credentials

- SSH brute force
- FTP authentication
- HTTP basic auth
- Database credentials
- Service authentication

## Exploitation Testing

### Web Exploits

1. **Open Exploitation tab**
2. **Enter target URL**
3. **Select test types:**
   - SQL Injection
   - XSS
   - LFI/RFI
   - Command Injection
   - XXE
   - SSRF
4. **Configure parameters**
5. **Start testing**

### Payload Management

- Custom payloads
- Payload encoding
- Bypass techniques
- Evasion methods

## Brute Force Attacks

### Credential Testing

1. **Open Brute Force tab**
2. **Configure target:**
   - Host and port
   - Service type (SSH, FTP, HTTP, etc.)
3. **Set credentials:**
   - Username list
   - Password list
4. **Configure attack:**
   - Thread count
   - Delay between attempts
5. **Start attack**

### Service Support

- SSH
- FTP
- HTTP Basic Auth
- MySQL
- PostgreSQL
- MSSQL
- Redis
- MongoDB

## Post-Exploitation

### System Enumeration

1. **Open Post-Exploitation tab**
2. **Select enumeration options:**
   - System information
   - Privilege escalation
   - Network services
   - Sensitive files
3. **Start enumeration**

### Privilege Escalation

- SUID/SGID binaries
- Sudo permissions
- Cron jobs
- Service permissions
- Kernel exploits

## Report Generation

### Creating Reports

1. **Open Reporting tab**
2. **Configure report:**
   - Title and client information
   - Report format (PDF/HTML)
   - Sections to include
3. **Generate report**

### Report Sections

- Executive Summary
- Vulnerability Summary
- Detailed Findings
- Recommendations
- Technical Details
- Appendices

## Plugin System

### Loading Plugins

1. **Open Plugins tab**
2. **Load plugins:** Click "Load Plugins"
3. **Select plugin:** Choose from available plugins
4. **Configure execution:**
   - Target
   - Options
5. **Execute plugin**

### Plugin Development

- Plugin template
- API documentation
- Best practices
- Security guidelines

## Configuration

### Application Settings

- **Scanning:** Default threads, timeouts
- **API:** Rate limiting, authentication
- **Database:** Storage, cleanup
- **Security:** Encryption, logging
- **GUI:** Theme, window size

### Scan Profiles

- **Quick:** Fast common port scan
- **Comprehensive:** Full port range scan
- **Stealth:** Slow, undetected scan
- **Web:** Web application focused
- **Database:** Database services
- **Network:** Infrastructure scan

### Database Management

- **Backup:** Configuration backup
- **Restore:** Restore from backup
- **Cleanup:** Remove old data
- **Optimization:** Performance tuning

## Best Practices

### Security

- Always obtain authorization before testing
- Use in controlled environments
- Follow responsible disclosure
- Keep tools updated
- Use strong authentication

### Performance

- Adjust thread counts based on target
- Use appropriate timeouts
- Monitor system resources
- Save results regularly
- Clean up old data

### Reporting

- Include executive summary
- Prioritize findings by severity
- Provide clear recommendations
- Include technical details
- Follow industry standards

## Troubleshooting

### Common Issues

- **Connection timeouts:** Increase timeout values
- **Memory usage:** Reduce thread count
- **Permission errors:** Run with appropriate privileges
- **Plugin errors:** Check plugin compatibility
- **Database errors:** Verify database configuration

### Support

- Check documentation
- Review error logs
- Update to latest version
- Contact support team
- Report bugs

## Legal and Ethical Use

### Important Notice

StrikeSuite is designed for authorized security testing only. Users must:

- Obtain explicit written permission
- Comply with applicable laws
- Use responsibly and ethically
- Follow responsible disclosure
- Respect privacy and confidentiality

### Liability

- Users are solely responsible for compliance
- Developers assume no liability for misuse
- Use at your own risk
- Follow ethical guidelines
- Respect target systems

---

**Remember:** With great power comes great responsibility. Use StrikeSuite ethically and legally.
