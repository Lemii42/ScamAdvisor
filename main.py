#!/usr/bin/env python3
"""
Scam Advisor - Website Trust Analyzer
Main entry point for the application
"""

import sys
import os
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QIcon

# Add the project root to Python path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from gui.main_window import MainWindow
from gui.theme_manager import ThemeManager
from config.settings import load_settings


def main():
    """Main application entry point"""
    # Create QApplication
    app = QApplication(sys.argv)
    app.setApplicationName("Scam Advisor")
    app.setApplicationVersion("1.0.0")

    # Load settings
    settings = load_settings()

    # Setup theme
    theme_manager = ThemeManager()
    theme_manager.apply_theme(settings.get('theme', 'dark'))

    # Create and show main window
    main_window = MainWindow(settings)  # This should work now with the fixed constructor

    main_window.show()

    # Start event loop
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()