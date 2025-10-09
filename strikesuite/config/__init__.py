#!/usr/bin/env python3
"""
StrikeSuite Configuration Management
Centralized configuration handling for the security testing framework
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional

class ConfigManager:
    """Centralized configuration management"""
    
    def __init__(self, config_dir: Optional[Path] = None):
        if config_dir is None:
            config_dir = Path(__file__).parent.parent.parent / "config"
        
        self.config_dir = config_dir
        self.config_dir.mkdir(exist_ok=True)
        
        # Default configurations
        self.defaults = {
            "database": {
                "path": "database/strikesuite.db",
                "backup_enabled": True,
                "backup_interval": 24
            },
            "scanning": {
                "default_timeout": 5,
                "max_threads": 50,
                "stealth_mode": False
            },
            "reporting": {
                "default_format": "PDF",
                "include_screenshots": True,
                "template_path": "reports/templates"
            },
            "gui": {
                "theme": "default",
                "window_size": [1200, 800],
                "auto_save": True
            }
        }
    
    def load_config(self, config_name: str) -> Dict[str, Any]:
        """Load configuration from file"""
        config_file = self.config_dir / f"{config_name}.json"
        
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Could not load {config_name}: {e}")
        
        # Return default if file doesn't exist or can't be loaded
        return self.defaults.get(config_name, {})
    
    def save_config(self, config_name: str, config_data: Dict[str, Any]) -> bool:
        """Save configuration to file"""
        config_file = self.config_dir / f"{config_name}.json"
        
        try:
            with open(config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            return True
        except Exception as e:
            print(f"Error: Could not save {config_name}: {e}")
            return False
    
    def get_setting(self, config_name: str, key: str, default: Any = None) -> Any:
        """Get a specific setting from configuration"""
        config = self.load_config(config_name)
        return config.get(key, default)
    
    def set_setting(self, config_name: str, key: str, value: Any) -> bool:
        """Set a specific setting in configuration"""
        config = self.load_config(config_name)
        config[key] = value
        return self.save_config(config_name, config)

# Global configuration manager instance
config_manager = ConfigManager()

__all__ = ['ConfigManager', 'config_manager']

