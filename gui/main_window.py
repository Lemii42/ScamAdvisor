"""
Main Application Window
Primary GUI interface
"""

import json
import os
from datetime import datetime
from PyQt5.QtWidgets import (QMainWindow, QVBoxLayout, QHBoxLayout,
                             QWidget, QLineEdit, QPushButton, QTextEdit,
                             QLabel, QProgressBar, QTabWidget, QMessageBox,
                             QListWidget)
from PyQt5.QtCore import QThread, pyqtSignal

# Import core modules
from core.url_analyzer import URLAnalyzer
from core.domain_info import DomainInfo
from core.ssl_checker import SSLChecker
from core.heuristics import HeuristicAnalyzer
from core.scoring_engine import ScoringEngine
from core.reputation_checker import ReputationChecker

class AnalysisThread(QThread):
    """Thread for running website analysis to prevent GUI freezing"""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, url: str, settings: dict):
        super().__init__()
        self.url = url
        self.settings = settings

    def run(self):
        try:
            # Run all analysis modules
            url_analyzer = URLAnalyzer()
            domain_info = DomainInfo()
            ssl_checker = SSLChecker()
            heuristic_analyzer = HeuristicAnalyzer()
            scoring_engine = ScoringEngine()

            # Get API keys from settings
            vt_api_key = self.settings.get('api_keys', {}).get('virustotal', '')
            otx_api_key = self.settings.get('api_keys', {}).get('otx', '')
            reputation_checker = ReputationChecker(vt_api_key, otx_api_key)

            # Step 1: URL analysis
            url_analysis = url_analyzer.analyze_url(self.url)
            domain = url_analysis['domain']

            # Step 2: Domain information
            whois_info = domain_info.get_whois_info(domain)
            dns_info = domain_info.get_dns_records(domain)

            # Step 3: SSL check
            ssl_info = ssl_checker.check_ssl_certificate(domain)

            # Step 4: Heuristic analysis
            heuristics = heuristic_analyzer.analyze_heuristics(self.url, domain)

            # Step 5: Reputation check (API calls)
            reputation_info = reputation_checker.check_all_reputation(self.url)

            # Combine results
            all_results = {
                'url_analysis': url_analysis,
                'whois_info': whois_info,
                'dns_info': dns_info,
                'ssl_info': ssl_info,
                'heuristics': heuristics,
                'reputation': reputation_info
            }

            # Step 6: Calculate risk score
            risk_assessment = scoring_engine.calculate_risk_score(all_results)
            all_results['risk_assessment'] = risk_assessment

            self.finished.emit(all_results)

        except Exception as e:
            self.error.emit(str(e))

class MainWindow(QMainWindow):
    def __init__(self, settings=None):
        super().__init__()
        self.settings = settings or {}
        self.current_results = None
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Scam Advisor - Website Trust Analyzer")
        self.setGeometry(100, 100, 1000, 800)

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        main_layout = QHBoxLayout()
        central_widget.setLayout(main_layout)

        # Left panel (History)
        left_panel = QWidget()
        left_layout = QVBoxLayout()
        left_panel.setLayout(left_layout)
        left_panel.setMaximumWidth(300)

        # History section
        history_label = QLabel("Search History")
        history_label.setStyleSheet("font-weight: bold; font-size: 14px; margin: 10px;")

        self.history_list = QListWidget()
        self.history_list.itemClicked.connect(self.load_history_item)

        clear_history_btn = QPushButton("Clear History")
        clear_history_btn.clicked.connect(self.clear_history)

        left_layout.addWidget(history_label)
        left_layout.addWidget(self.history_list)
        left_layout.addWidget(clear_history_btn)

        # Right panel (Main content)
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_panel.setLayout(right_layout)

        # URL input section
        url_layout = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter website URL to analyze...")
        self.url_input.returnPressed.connect(self.start_analysis)

        self.analyze_btn = QPushButton("🔍 Analyze Website")
        self.analyze_btn.clicked.connect(self.start_analysis)

        self.save_btn = QPushButton("💾 Save to History")
        self.save_btn.clicked.connect(self.save_current_search)
        self.save_btn.setEnabled(False)

        url_layout.addWidget(QLabel("Website URL:"))
        url_layout.addWidget(self.url_input)
        url_layout.addWidget(self.analyze_btn)
        url_layout.addWidget(self.save_btn)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)

        # Results display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)

        # Add widgets to right layout
        right_layout.addLayout(url_layout)
        right_layout.addWidget(self.progress_bar)
        right_layout.addWidget(self.results_display)

        # Add panels to main layout
        main_layout.addWidget(left_panel)
        main_layout.addWidget(right_panel)

        # Load history
        self.load_history()

    def load_history(self):
        """Load search history from file"""
        try:
            history_file = os.path.join('data', 'history.json')
            if os.path.exists(history_file):
                with open(history_file, 'r') as f:
                    history_data = json.load(f)
                    for item in history_data:
                        self.history_list.addItem(f"{item['url']} - {item['risk_level']}")
        except Exception as e:
            print(f"Error loading history: {e}")

    def save_current_search(self):
        """Save current search to history"""
        if hasattr(self, 'current_results'):
            try:
                # Create data directory if it doesn't exist
                os.makedirs('data', exist_ok=True)

                history_file = os.path.join('data', 'history.json')
                history_data = []

                # Load existing history
                if os.path.exists(history_file):
                    with open(history_file, 'r') as f:
                        history_data = json.load(f)

                # Add new entry
                new_entry = {
                    'url': self.current_results['url_analysis']['normalized_url'],
                    'risk_level': self.current_results['risk_assessment']['risk_level'],
                    'score': self.current_results['risk_assessment']['overall_score'],
                    'timestamp': datetime.now().isoformat()
                }

                # Remove duplicates
                history_data = [item for item in history_data if item['url'] != new_entry['url']]
                history_data.insert(0, new_entry)  # Add to beginning

                # Keep only last 50 entries
                history_data = history_data[:50]

                # Save history
                with open(history_file, 'w') as f:
                    json.dump(history_data, f, indent=2)

                # Update history list
                self.history_list.clear()
                for item in history_data:
                    self.history_list.addItem(f"{item['url']} - {item['risk_level']}")

                QMessageBox.information(self, "Saved", "Search saved to history!")

            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not save history: {e}")

    def load_history_item(self, item):
        """Load a history item into the search box"""
        text = item.text()
        url = text.split(' - ')[0]  # Extract URL from display text
        self.url_input.setText(url)

    def clear_history(self):
        """Clear all search history"""
        reply = QMessageBox.question(self, "Clear History",
                                   "Are you sure you want to clear all search history?",
                                   QMessageBox.Yes | QMessageBox.No)

        if reply == QMessageBox.Yes:
            try:
                history_file = os.path.join('data', 'history.json')
                if os.path.exists(history_file):
                    os.remove(history_file)
                self.history_list.clear()
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not clear history: {e}")

    def start_analysis(self):
        """Start website analysis in separate thread"""
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a URL to analyze")
            return

        # Disable UI during analysis
        self.analyze_btn.setEnabled(False)
        self.save_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress

        # Start analysis thread
        self.analysis_thread = AnalysisThread(url, self.settings)
        self.analysis_thread.finished.connect(self.on_analysis_complete)
        self.analysis_thread.error.connect(self.on_analysis_error)
        self.analysis_thread.start()

    def on_analysis_complete(self, results):
        """Handle completed analysis"""
        self.analyze_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.save_btn.setEnabled(True)  # Enable save button

        # Store current results for saving
        self.current_results = results

        # Display results (enhanced with API data)
        self.display_enhanced_results(results)

    def on_analysis_error(self, error_message):
        """Handle analysis errors"""
        self.analyze_btn.setEnabled(True)
        self.save_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        QMessageBox.critical(self, "Analysis Error", f"An error occurred: {error_message}")

    def display_enhanced_results(self, results):
        """Display results with API reputation data"""
        risk = results['risk_assessment']
        reputation = results.get('reputation', {})

        output = f"""
=== SCAM ADVISOR ANALYSIS REPORT ===

Website: {results['url_analysis']['normalized_url']}
Risk Level: {risk['risk_level']}
Overall Score: {risk['overall_score']}/100

RISK FACTORS:
"""
        for factor in risk['risk_factors']:
            output += f"• {factor}\n"

        # Add reputation information
        output += f"""
REPUTATION ANALYSIS:
"""

        # VirusTotal results
        vt_data = reputation.get('virustotal', {})
        if 'detected' in vt_data:
            output += f"• VirusTotal: {vt_data['detection_ratio']} vendors detected\n"
        elif 'error' in vt_data:
            output += f"• VirusTotal: {vt_data['error']}\n"
        else:
            output += "• VirusTotal: No data available\n"

        # OTX results
        otx_data = reputation.get('alienvault_otx', {})
        if 'pulse_count' in otx_data:
            output += f"• AlienVault OTX: {otx_data['pulse_count']} threat intelligence pulses\n"
        elif 'error' in otx_data:
            output += f"• AlienVault OTX: {otx_data['error']}\n"
        else:
            output += "• AlienVault OTX: No data available\n"

        output += f"""
DETAILED ANALYSIS:
- Domain: {results['url_analysis']['domain']}
- HTTPS: {'Yes' if results['url_analysis']['is_https'] else 'No'}
- Heuristic Score: {results['heuristics']['heuristic_score']}/100
- Reputation Score: {reputation.get('reputation_score', 0)}/100
"""

        self.results_display.setPlainText(output)