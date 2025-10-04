# StrikeSuite Plugin Development Guide

## Overview
This guide provides comprehensive information for developing custom plugins for StrikeSuite v1.0. Plugins allow you to extend the toolkit's functionality with custom security testing modules, tools, and features.

## Plugin Architecture

### Plugin Structure
Each plugin should follow this directory structure:
```
plugin_name/
├── __init__.py
├── plugin.py
├── config.json
├── requirements.txt
└── README.md
```

### Base Plugin Class
All plugins must inherit from the `StrikeSuitePlugin` base class:

```python
from plugins.template import StrikeSuitePlugin

class MyPlugin(StrikeSuitePlugin):
    def __init__(self):
        self.name = "My Custom Plugin"
        self.version = "1.0.0"
        self.description = "Description of what this plugin does"
        self.author = "Your Name"
        self.category = "network"  # network, web, api, etc.
    
    def execute(self, target, options=None):
        # Your plugin logic here
        return {"status": "success", "results": []}
```

## Plugin Development

### 1. Plugin Template
Start with the provided template:

```python
#!/usr/bin/env python3
"""
My Custom Security Plugin
Description of plugin functionality
"""

import requests
import json
from typing import Dict, List, Any

class MySecurityPlugin:
    """Custom security testing plugin"""
    
    def __init__(self):
        self.name = "My Security Plugin"
        self.version = "1.0.0"
        self.description = "Custom security testing functionality"
        self.author = "Your Name"
        self.category = "web"
    
    def execute(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Main plugin execution method
        
        Args:
            target: Target to test
            options: Additional options
            
        Returns:
            Dictionary with results
        """
        if options is None:
            options = {}
        
        results = {
            "target": target,
            "status": "success",
            "findings": [],
            "errors": []
        }
        
        try:
            # Your plugin logic here
            pass
        except Exception as e:
            results["status"] = "error"
            results["errors"].append(str(e))
        
        return results
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is suitable for this plugin"""
        # Implement validation logic
        return True
    
    def get_requirements(self) -> List[str]:
        """Return list of required dependencies"""
        return ["requests", "beautifulsoup4"]

# Plugin instance
plugin = MySecurityPlugin()
```

### 2. Configuration File
Create a `config.json` file for your plugin:

```json
{
    "name": "My Security Plugin",
    "version": "1.0.0",
    "description": "Custom security testing functionality",
    "author": "Your Name",
    "category": "web",
    "settings": {
        "timeout": 30,
        "threads": 10,
        "verbose": false
    },
    "dependencies": [
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0"
    ]
}
```

### 3. Requirements File
Create a `requirements.txt` file:

```
requests>=2.28.0
beautifulsoup4>=4.11.0
urllib3>=1.26.0
```

## Plugin Categories

### Network Security Plugins
- Port scanning
- Service enumeration
- Network mapping
- Protocol analysis

### Web Security Plugins
- Web application scanning
- Directory enumeration
- SQL injection testing
- XSS testing

### API Security Plugins
- API endpoint discovery
- Authentication testing
- Authorization testing
- Input validation testing

### System Security Plugins
- OS fingerprinting
- Service fingerprinting
- Vulnerability scanning
- Configuration analysis

## Best Practices

### 1. Error Handling
Always implement proper error handling:

```python
def execute(self, target, options=None):
    try:
        # Plugin logic
        pass
    except requests.RequestException as e:
        return {"status": "error", "message": f"Network error: {e}"}
    except Exception as e:
        return {"status": "error", "message": f"Unexpected error: {e}"}
```

### 2. Input Validation
Validate all inputs:

```python
def validate_target(self, target):
    if not target:
        return False
    if not isinstance(target, str):
        return False
    # Additional validation
    return True
```

### 3. Logging
Use proper logging:

```python
import logging

logger = logging.getLogger(__name__)

def execute(self, target, options=None):
    logger.info(f"Starting plugin execution on {target}")
    # Plugin logic
    logger.info("Plugin execution completed")
```

### 4. Configuration
Use configuration options:

```python
def execute(self, target, options=None):
    if options is None:
        options = {}
    
    timeout = options.get('timeout', 30)
    threads = options.get('threads', 10)
    verbose = options.get('verbose', False)
```

### 5. Results Format
Follow consistent results format:

```python
def execute(self, target, options=None):
    results = {
        "target": target,
        "status": "success",  # success, error, warning
        "findings": [],
        "statistics": {
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "warnings": 0
        },
        "errors": [],
        "warnings": [],
        "execution_time": 0.0
    }
    
    return results
```

## Plugin Testing

### 1. Unit Tests
Create unit tests for your plugin:

```python
import unittest
from my_plugin import MySecurityPlugin

class TestMyPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = MySecurityPlugin()
    
    def test_plugin_initialization(self):
        self.assertEqual(self.plugin.name, "My Security Plugin")
        self.assertEqual(self.plugin.version, "1.0.0")
    
    def test_target_validation(self):
        self.assertTrue(self.plugin.validate_target("example.com"))
        self.assertFalse(self.plugin.validate_target(""))
    
    def test_plugin_execution(self):
        results = self.plugin.execute("example.com")
        self.assertIn("status", results)
        self.assertIn("findings", results)

if __name__ == '__main__':
    unittest.main()
```

### 2. Integration Tests
Test plugin integration with StrikeSuite:

```python
def test_plugin_integration():
    from core.plugin_manager import PluginManager
    
    manager = PluginManager()
    plugin = manager.load_plugin("my_plugin")
    
    results = plugin.execute("test-target")
    assert results["status"] == "success"
```

## Plugin Distribution

### 1. Package Structure
Organize your plugin for distribution:

```
my_security_plugin/
├── __init__.py
├── plugin.py
├── config.json
├── requirements.txt
├── README.md
├── tests/
│   ├── __init__.py
│   └── test_plugin.py
└── setup.py
```

### 2. Setup Script
Create a `setup.py` file:

```python
from setuptools import setup, find_packages

setup(
    name="my-security-plugin",
    version="1.0.0",
    description="Custom security testing plugin for StrikeSuite",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0"
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
)
```

### 3. Documentation
Include comprehensive documentation:

```markdown
# My Security Plugin

## Description
Brief description of what this plugin does.

## Installation
```bash
pip install my-security-plugin
```

## Usage
```python
from my_security_plugin import MySecurityPlugin

plugin = MySecurityPlugin()
results = plugin.execute("target.com")
```

## Configuration
Describe configuration options.

## Requirements
List system and Python requirements.

## License
MIT License
```

## Plugin Examples

### 1. Simple Port Scanner Plugin
```python
import socket
from concurrent.futures import ThreadPoolExecutor

class PortScannerPlugin:
    def __init__(self):
        self.name = "Port Scanner Plugin"
        self.version = "1.0.0"
        self.description = "Simple port scanner"
    
    def execute(self, target, options=None):
        if options is None:
            options = {}
        
        ports = options.get('ports', [22, 80, 443, 8080])
        threads = options.get('threads', 10)
        
        results = {
            "target": target,
            "status": "success",
            "open_ports": [],
            "closed_ports": []
        }
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(self.scan_port, target, port) for port in ports]
            for future in futures:
                port, is_open = future.result()
                if is_open:
                    results["open_ports"].append(port)
                else:
                    results["closed_ports"].append(port)
        
        return results
    
    def scan_port(self, target, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            return port, result == 0
        except:
            return port, False
```

### 2. Web Directory Scanner Plugin
```python
import requests
from concurrent.futures import ThreadPoolExecutor

class DirectoryScannerPlugin:
    def __init__(self):
        self.name = "Directory Scanner Plugin"
        self.version = "1.0.0"
        self.description = "Web directory enumeration"
    
    def execute(self, target, options=None):
        if options is None:
            options = {}
        
        wordlist = options.get('wordlist', ['admin', 'login', 'test'])
        threads = options.get('threads', 10)
        
        results = {
            "target": target,
            "status": "success",
            "found_directories": [],
            "errors": []
        }
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(self.check_directory, target, directory) for directory in wordlist]
            for future in futures:
                directory, exists = future.result()
                if exists:
                    results["found_directories"].append(directory)
        
        return results
    
    def check_directory(self, target, directory):
        try:
            url = f"{target.rstrip('/')}/{directory}"
            response = requests.get(url, timeout=5)
            return directory, response.status_code == 200
        except:
            return directory, False
```

## Troubleshooting

### Common Issues

1. **Plugin not loading**: Check file permissions and Python path
2. **Import errors**: Ensure all dependencies are installed
3. **Configuration errors**: Validate JSON configuration files
4. **Execution errors**: Check error handling and logging

### Debug Mode
Enable debug mode for troubleshooting:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Contributing

### Guidelines
1. Follow PEP 8 style guidelines
2. Include comprehensive tests
3. Document all functions and classes
4. Use type hints where appropriate
5. Follow security best practices

### Submission Process
1. Fork the repository
2. Create a feature branch
3. Implement your plugin
4. Add tests and documentation
5. Submit a pull request

## Resources

- [StrikeSuite Documentation](docs/)
- [Plugin Template](plugins/template.py)
- [Example Plugins](plugins/)
- [API Reference](docs/api_reference.md)

---

*For questions and support, please refer to the StrikeSuite documentation or contact the development team.*
