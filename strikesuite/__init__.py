#!/usr/bin/env python3
"""
StrikeSuite - Advanced Cybersecurity Testing Framework
A comprehensive security testing platform with GUI interface
"""

__version__ = "1.0.0"
__author__ = "StrikeSuite Team"
__email__ = "team@strikesuite.com"
__description__ = "Advanced Cybersecurity Testing Framework"

# Import main components
from .core import *
from .gui import *
from .utils import *

# Version info
__all__ = [
    '__version__',
    '__author__', 
    '__email__',
    '__description__'
]

