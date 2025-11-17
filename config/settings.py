"""
Settings Management
Load and save application configuration
"""

import configparser
import os
from typing import Dict, Any

def load_settings() -> Dict[str, Any]:
    """Load application settings from INI file"""
    config = configparser.ConfigParser()
    settings_file = os.path.join(os.path.dirname(__file__), 'settings.ini')

    # Default settings
    default_settings = {
        'theme': 'dark',
        'api_keys': {
            'virustotal': '',
            'abuseipdb': '',
            'otx': ''
        },
        'scanning': {
            'timeout': '30',
            'enable_caching': 'true'
        }
    }

    # Create default settings file if it doesn't exist
    if not os.path.exists(settings_file):
        save_settings(default_settings)
        return default_settings

    # Load existing settings
    config.read(settings_file)
    settings = {}

    for section in config.sections():
        settings[section] = {}
        for key, value in config.items(section):
            settings[section][key] = value

    return settings

def save_settings(settings: Dict[str, Any]):
    """Save application settings to INI file"""
    config = configparser.ConfigParser()

    for section, options in settings.items():
        config[section] = options

    settings_file = os.path.join(os.path.dirname(__file__), 'settings.ini')
    with open(settings_file, 'w') as f:
        config.write(f)