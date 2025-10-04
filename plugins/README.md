# StrikeSuite Plugin Development Guide

## Overview
This directory contains plugins that extend StrikeSuite's functionality. Plugins allow you to add custom security testing modules, tools, and features.

## Plugin Structure
Each plugin should follow this structure:
```
plugin_name/
├── __init__.py
├── plugin.py
├── config.json
└── README.md
```

## Plugin Template
Use `template.py` as a starting point for new plugins.

## Available Plugins
- **advanced_api_tester.py** - Advanced API security testing
- **subdomain_enum.py** - Subdomain enumeration
- **directory_bruteforce.py** - Directory brute force attacks
- **ssl_analyzer.py** - SSL/TLS security analysis
- **wordpress_scanner.py** - WordPress security scanner

## Development Guidelines
1. Follow the plugin interface defined in `template.py`
2. Include proper error handling
3. Add configuration options via `config.json`
4. Document your plugin in its README.md
5. Test thoroughly before submission

## Installation
Plugins are automatically loaded from this directory when StrikeSuite starts.
