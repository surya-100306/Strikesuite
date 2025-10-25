#!/bin/bash
# StrikeSuite CLI Launcher Script

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Change to the StrikeSuite directory
cd "$SCRIPT_DIR"

# Run the CLI
python3 strikesuite_cli.py "$@"

