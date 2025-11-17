"""
URL Analysis Module
Handles URL normalization, parsing, and redirect tracking
"""

from urllib.parse import urlparse, urlunparse
import requests
from typing import Dict, Any


class URLAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def normalize_url(self, url: str) -> str:
        """Normalize URL for consistent processing"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        parsed = urlparse(url)
        return urlunparse((
            parsed.scheme,
            parsed.netloc.lower(),
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Comprehensive URL analysis"""
        normalized_url = self.normalize_url(url)
        parsed = urlparse(normalized_url)

        return {
            'original_url': url,
            'normalized_url': normalized_url,
            'domain': parsed.netloc,
            'scheme': parsed.scheme,
            'path': parsed.path,
            'query': parsed.query,
            'fragment': parsed.fragment,
            'is_https': parsed.scheme == 'https'
        }