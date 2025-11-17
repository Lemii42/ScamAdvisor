"""
Reputation Checker Module
VirusTotal and AlienVault OTX API integration
"""

import requests
import time
from typing import Dict, Any, List
import hashlib


class ReputationChecker:
    def __init__(self, virustotal_api_key: str = "", otx_api_key: str = ""):
        self.vt_api_key = virustotal_api_key
        self.otx_api_key = otx_api_key
        self.session = requests.Session()

        # API endpoints
        self.vt_url_scan = "https://www.virustotal.com/vtapi/v2/url/scan"
        self.vt_url_report = "https://www.virustotal.com/vtapi/v2/url/report"
        self.otx_url = "https://otx.alienvault.com/api/v1/indicators/url/"

        # Headers
        self.session.headers.update({
            'User-Agent': 'ScamAdvisor/1.0'
        })

    def check_virustotal(self, url: str) -> Dict[str, Any]:
        """Check URL reputation with VirusTotal"""
        if not self.vt_api_key or self.vt_api_key == "YOUR_VIRUSTOTAL_API_KEY":
            return {'error': 'VirusTotal API key not configured'}

        try:
            # Get URL report
            params = {
                'apikey': self.vt_api_key,
                'resource': url,
                'scan': 0  # Don't force rescan
            }

            # Add timeout to prevent hanging
            response = self.session.get(self.vt_url_report, params=params, timeout=15)

            if response.status_code == 200:
                data = response.json()

                if data['response_code'] == 1:
                    # URL found in database
                    positives = data.get('positives', 0)
                    total = data.get('total', 1)

                    return {
                        'detected': positives,
                        'total': total,
                        'detection_ratio': f"{positives}/{total}",
                        'scan_date': data.get('scan_date'),
                        'permalink': data.get('permalink'),
                        'engines': data.get('scans', {})
                    }
                else:
                    # URL not found - this is common for new domains
                    return {
                        'message': 'URL not in VirusTotal database (new/unknown domain)',
                        'response_code': 0
                    }
            elif response.status_code == 204:
                return {'error': 'VirusTotal API rate limit exceeded'}
            elif response.status_code == 403:
                return {'error': 'VirusTotal API key invalid or unauthorized'}
            else:
                return {'error': f'VirusTotal API error: {response.status_code}'}

        except requests.exceptions.Timeout:
            return {'error': 'VirusTotal request timed out'}
        except requests.exceptions.ConnectionError:
            return {'error': 'Network connection failed'}
        except Exception as e:
            return {'error': f'VirusTotal check failed: {str(e)}'}

    def check_otx(self, url: str) -> Dict[str, Any]:
        """Check URL reputation with AlienVault OTX"""
        if not self.otx_api_key or self.otx_api_key == "YOUR_OTX_API_KEY":
            return {'error': 'OTX API key not configured'}

        try:
            # Create hash of the URL for OTX
            url_hash = hashlib.md5(url.encode()).hexdigest()

            headers = {
                'X-OTX-API-KEY': self.otx_api_key
            }

            # Check URL reputation
            response = self.session.get(f"{self.otx_url}{url_hash}/general", headers=headers)

            if response.status_code == 200:
                data = response.json()

                # Extract pulse information (threat intelligence)
                pulses = data.get('pulse_info', {}).get('pulses', [])
                pulse_count = len(pulses)

                # Extract malware analysis if available
                analysis = data.get('analysis', {})

                return {
                    'pulse_count': pulse_count,
                    'malware_families': analysis.get('results', {}),
                    'reputation': data.get('reputation', 0),
                    'threat_score': pulse_count * 10,  # Simple threat scoring
                    'pulses': pulses[:5]  # First 5 pulses
                }
            else:
                return {'error': f'OTX API request failed: {response.status_code}'}

        except Exception as e:
            return {'error': f'OTX check failed: {str(e)}'}

    def check_all_reputation(self, url: str) -> Dict[str, Any]:
        """Run all reputation checks"""
        results = {}

        # VirusTotal check
        vt_result = self.check_virustotal(url)
        results['virustotal'] = vt_result

        # OTX check
        otx_result = self.check_otx(url)
        results['alienvault_otx'] = otx_result

        # Calculate overall reputation score
        reputation_score = 0
        reputation_factors = []

        # VirusTotal scoring
        if 'detected' in vt_result:
            positives = vt_result['detected']
            total = vt_result['total']
            if positives > 0:
                reputation_score += min(positives * 10, 70)


        # OTX scoring
        if 'pulse_count' in otx_result:
            pulse_count = otx_result['pulse_count']
            if pulse_count > 0:
                reputation_score += min(pulse_count * 5, 50)


        results['reputation_score'] = min(reputation_score, 100)
        results['reputation_factors'] = reputation_factors

        return results