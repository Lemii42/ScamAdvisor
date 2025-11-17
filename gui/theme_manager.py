"""
Theme Management
Handle dark/light mode and styling
"""

from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtCore import Qt


class ThemeManager:
    def apply_theme(self, theme_name: str):
        """Apply dark or light theme to application"""
        if theme_name == 'dark':
            self.apply_dark_theme()
        else:
            self.apply_light_theme()

    def apply_dark_theme(self):
        """Apply dark theme styling"""
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.HighlightedText, Qt.black)

        from PyQt5.QtWidgets import QApplication
        QApplication.setPalette(palette)

    def apply_light_theme(self):
        """Apply light theme (system default)"""
        from PyQt5.QtWidgets import QApplication
        QApplication.setPalette(QApplication.style().standardPalette())