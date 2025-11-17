"""
Heuristic Analysis Module
Detect suspicious patterns and characteristics
"""

from urllib.parse import urlparse
import re
from typing import Dict, Any
import idna

class HeuristicAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'secure', 'account', 'verify', 'banking',
            'paypal', 'ebay', 'amazon', 'password', 'update',
            'signin', 'authenticate', 'confirm', 'security'
        ]

        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club']

        self.legitimate_domains = [
            'google.com', 'github.com', 'microsoft.com', 'apple.com',
            'amazon.com', 'paypal.com', 'facebook.com', 'twitter.com'
        ]

    def analyze_heuristics(self, url: str, domain: str) -> Dict[str, Any]:
        """Run heuristic analysis for scam detection"""
        score = 0
        warnings = []

        # Check if domain is in legitimate list (negative scoring)
        if any(legit in domain for legit in self.legitimate_domains):
            score -= 20  # Bonus for known legitimate sites

        # Check for suspicious TLDs
        if any(domain.endswith(tld) for tld in self.suspicious_tlds):
            score += 30
            warnings.append("Suspicious TLD detected")

        # Check for IP address in domain
        ip_pattern = r'\d+\.\d+\.\d+\.\d+'
        if re.search(ip_pattern, domain):
            score += 25
            warnings.append("IP address used instead of domain name")

        # Check for excessive subdomains
        subdomain_count = domain.count('.')
        if subdomain_count >= 4:
            score += 20
            warnings.append("Excessive number of subdomains")
        elif subdomain_count == 3:
            score += 10
            warnings.append("Multiple subdomains detected")

        # Check for suspicious keywords in domain/path
        url_lower = url.lower()
        keyword_matches = [kw for kw in self.suspicious_keywords if kw in url_lower]
        if keyword_matches:
            score += len(keyword_matches) * 8
            warnings.append(f"Suspicious keywords found: {', '.join(keyword_matches)}")

        # Check URL length
        if len(url) > 75:
            score += min((len(url) - 75) // 5, 25)  # Max 25 points for long URLs
            warnings.append("URL is unusually long")

        # Check for hyphens in domain (common in phishing)
        if domain.count('-') >= 3:
            score += 15
            warnings.append("Multiple hyphens in domain (phishing tactic)")

        # Check for homograph attacks (Punycode)
        try:
            ascii_domain = idna.decode(domain)
            if ascii_domain != domain:
                score += 40
                warnings.append("Punycode/IDN domain detected (possible homograph attack)")
        except:
            pass  # Not a punycode domain

        # Check for HTTP (not HTTPS)
        if url.startswith('http://'):
            score += 30
            warnings.append("Website uses HTTP instead of HTTPS")

        return {
            'heuristic_score': max(0, min(score, 100)),  # Ensure score between 0-100
            'warnings': warnings,
            'suspicious_keywords_found': keyword_matches,
            'subdomain_count': subdomain_count
        }