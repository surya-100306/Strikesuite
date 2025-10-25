#!/usr/bin/env python3
"""
StrikeSuite CLI Entry Point
Direct command-line interface for StrikeSuite
"""

import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import and run CLI
if __name__ == "__main__":
    try:
        from strikesuite.cli import main
        sys.exit(main())
    except ImportError as e:
        print(f"❌ Failed to import StrikeSuite CLI: {e}")
        print("Make sure you're running this from the StrikeSuite directory")
        sys.exit(1)
    except Exception as e:
        print(f"❌ CLI Error: {e}")
        sys.exit(1)

