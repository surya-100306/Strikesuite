"""
StrikeSuite GUI Package
Graphical user interface components
"""

__version__ = "1.0.0"

# Import with error handling
try:
    from .main_window import MainWindow
except ImportError:
    MainWindow = None

__all__ = ['MainWindow']
