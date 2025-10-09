#!/usr/bin/env python3
"""
StrikeSuite Installation Script
"""

from setuptools import setup, find_packages
import os

# Read README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="strikesuite",
    version="1.0.0",
    author="StrikeSuite Team",
    author_email="team@strikesuite.com",
    description="Advanced Cybersecurity Testing Framework",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/strikesuite/strikesuite",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "strikesuite=strikesuite.main:main",
            "strikesuite-cli=strikesuite.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "strikesuite": [
            "*.txt", "*.md", "*.json", "*.html", "*.css", "*.js",
            "wordlists/*.txt",
            "payloads/**/*.py", "payloads/**/*.sh", "payloads/**/*.ps1", 
            "payloads/**/*.php", "payloads/**/*.asp", "payloads/**/*.jsp",
            "assets/**/*.ico", "assets/**/*.png", "assets/**/*.jpg", "assets/**/*.gif",
            "config/*.json",
            "templates/*.html", "templates/*.md"
        ],
    },
    keywords="security, penetration-testing, vulnerability-assessment, cybersecurity",
    project_urls={
        "Bug Reports": "https://github.com/strikesuite/strikesuite/issues",
        "Source": "https://github.com/strikesuite/strikesuite",
        "Documentation": "https://strikesuite.readthedocs.io/",
    },
    zip_safe=False,
    extras_require={
        "dev": [
            "black>=22.0.0",
            "flake8>=5.0.0", 
            "mypy>=1.0.0",
            "pre-commit>=2.20.0",
            "pytest>=7.1.0",
            "pytest-cov>=4.0.0"
        ],
        "gui": [
            "PyQt5>=5.15.0"
        ],
        "advanced": [
            "scapy>=2.4.5",
            "selenium>=4.8.0",
            "sqlalchemy>=1.4.0"
        ]
    }
)

