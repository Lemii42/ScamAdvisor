"""
Risk Scoring Engine
Calculate overall risk score based on multiple factors
"""

from typing import Dict, Any
from datetime import datetime

class ScoringEngine:
    def calculate_risk_score(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk score from all analysis modules"""

        total_score = 0
        factors = []

        # SSL factors (25% weight)
        ssl_score = 0
        ssl_info = analysis_results.get('ssl_info', {})

        if 'error' in ssl_info:
            ssl_score += 80
            factors.append("SSL certificate error or cannot verify")
        elif ssl_info:
            if not ssl_info.get('is_valid', False):
                ssl_score += 70
                factors.append("SSL certificate expired or invalid")
            elif ssl_info.get('days_until_expiry', 0) < 7:
                ssl_score += 50
                factors.append("SSL certificate expiring very soon (<7 days)")
            elif ssl_info.get('days_until_expiry', 0) < 30:
                ssl_score += 30
                factors.append("SSL certificate expiring soon (<30 days)")
            else:
                ssl_score += 10  # Good SSL certificate
                factors.append("Valid SSL certificate present")
        else:
            ssl_score += 60
            factors.append("No SSL certificate information available")

        total_score += ssl_score * 0.25

        # Heuristic factors (35% weight)
        if 'heuristics' in analysis_results:
            heuristic_score = analysis_results['heuristics']['heuristic_score']
            total_score += heuristic_score * 0.35
            # Use helper to avoid duplicates
            self._add_factors_without_duplicates(factors, analysis_results['heuristics']['warnings'])

        # Reputation factors (25% weight)
        reputation_score = 0
        reputation_info = analysis_results.get('reputation', {})

        # VirusTotal reputation scoring
        vt_data = reputation_info.get('virustotal', {})
        if 'detected' in vt_data:
            positives = vt_data['detected']
            total = vt_data.get('total', 1)

            if positives > 0:
                reputation_score += min(positives * 15, 70)
                # ENHANCED: Check for existing similar factors before adding
                vendor_text = f"Detected by {positives} security vendor"
                if not any(vendor_text in factor for factor in factors):
                    if positives >= 10:
                        factors.append(f"🚨 CRITICAL MALWARE: Detected by {positives} security vendors")
                    elif positives >= 5:
                        factors.append(f"🚨 MALWARE: Detected by {positives} security vendors")
                    elif positives >= 2:
                        factors.append(f"⚠️ Suspicious: Detected by {positives} security vendors")
                    else:
                        factors.append(f"🟡 Monitored: Detected by {positives} security vendor")

        # AlienVault OTX reputation scoring
        otx_data = reputation_info.get('alienvault_otx', {})
        if 'pulse_count' in otx_data:
            pulse_count = otx_data['pulse_count']
            if pulse_count > 0:
                reputation_score += min(pulse_count * 8, 60)
                # ENHANCED: Check for existing similar factors
                pulse_text = f"Found in {pulse_count} intelligence feed"
                if not any(pulse_text in factor for factor in factors):
                    if pulse_count >= 5:
                        factors.append(f"🚨 ACTIVE THREAT: Found in {pulse_count} intelligence feeds")
                    elif pulse_count >= 2:
                        factors.append(f"⚠️ Known Threat: Found in {pulse_count} intelligence feeds")
                    else:
                        factors.append(f"🟡 Monitored: Found in {pulse_count} intelligence feed")

        # Add any additional reputation factors with duplicate checking
        existing_factors = set(factors)
        for factor in reputation_info.get('reputation_factors', []):
            # Skip if it contains vendor detection text (already handled above)
            if "Detected by" in factor and any("Detected by" in f for f in factors):
                continue
            if factor not in existing_factors:
                factors.append(factor)
                existing_factors.add(factor)

        total_score += reputation_score * 0.25

        # Domain age factors (10% weight)
        domain_age_score = self._calculate_domain_age_score(analysis_results.get('whois_info', {}))
        total_score += domain_age_score * 0.10
        if domain_age_score >= 80:
            self._add_factor_if_not_exists(factors, "🚨 Brand new domain (created < 30 days ago)")
        elif domain_age_score >= 60:
            self._add_factor_if_not_exists(factors, "⚠️ Very new domain (created < 3 months ago)")
        elif domain_age_score >= 40:
            self._add_factor_if_not_exists(factors, "🟡 New domain (created < 1 year ago)")

        # DNS factors (5% weight)
        dns_info = analysis_results.get('dns_info', {})
        dns_score = self._calculate_dns_score(dns_info)
        total_score += dns_score * 0.05

        # Add DNS-specific factors with duplicate checking
        suspicious_dns = dns_info.get('suspicious_dns_patterns', [])
        for dns_factor in suspicious_dns:
            self._add_factor_if_not_exists(factors, dns_factor)

        if dns_score > 25:
            self._add_factor_if_not_exists(factors, "Suspicious DNS configuration")
        elif dns_score > 10:
            self._add_factor_if_not_exists(factors, "Unusual DNS configuration")

        # Final duplicate removal (safety net)
        factors = self._remove_duplicate_factors(factors)

        # Determine risk level
        risk_level = self._get_risk_level(total_score)

        return {
            'overall_score': min(round(total_score), 100),
            'risk_level': risk_level,
            'risk_factors': factors,
            'components': {
                'ssl_score': ssl_score,
                'heuristic_score': analysis_results.get('heuristics', {}).get('heuristic_score', 0),
                'reputation_score': reputation_score,
                'domain_age_score': domain_age_score,
                'dns_score': dns_score
            }
        }

    def _add_factors_without_duplicates(self, factors: list, new_factors: list):
        """Add new factors while avoiding duplicates"""
        existing_set = set(factors)
        for factor in new_factors:
            if factor not in existing_set:
                factors.append(factor)
                existing_set.add(factor)

    def _add_factor_if_not_exists(self, factors: list, new_factor: str):
        """Add a factor only if it doesn't already exist"""
        if new_factor not in factors:
            factors.append(new_factor)

    def _remove_duplicate_factors(self, factors: list) -> list:
        """Remove duplicate factors while preserving order"""
        seen = set()
        unique_factors = []
        for factor in factors:
            # Normalize the factor for comparison
            normalized = factor.lower().replace(' ', '')
            if normalized not in seen:
                seen.add(normalized)
                unique_factors.append(factor)
        return unique_factors

    def _calculate_domain_age_score(self, whois_info: Dict[str, Any]) -> int:
        """Calculate score based on domain age with more granular scoring"""
        try:
            creation_date = whois_info.get('creation_date')
            if creation_date:
                # If we have creation date, newer domains get higher scores
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]

                if hasattr(creation_date, 'year'):
                    current_date = datetime.now()

                    # Handle both date objects and strings
                    if isinstance(creation_date, str):
                        try:
                            creation_date = datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')
                        except:
                            creation_date = datetime.strptime(creation_date.split('T')[0], '%Y-%m-%d')

                    domain_age_days = (current_date - creation_date).days

                    if domain_age_days < 7:
                        return 90   # Less than 1 week old - extremely suspicious
                    elif domain_age_days < 30:
                        return 80   # Less than 30 days old - very suspicious
                    elif domain_age_days < 90:
                        return 60   # Less than 3 months old
                    elif domain_age_days < 180:
                        return 45   # Less than 6 months old
                    elif domain_age_days < 365:
                        return 30   # Less than 1 year old
                    elif domain_age_days < 730:
                        return 15   # 1-2 years old
                    else:
                        return 5    # Over 2 years old - established domain

        except Exception as e:
            # If we can't calculate age, assume it's suspicious
            print(f"Domain age calculation error: {e}")

        return 35  # Default score for unknown age (moderately suspicious)

    def _calculate_dns_score(self, dns_info: Dict[str, Any]) -> int:
        """Calculate score based on DNS configuration with enhanced checks"""
        score = 0

        # Check if domain has MX records (email capability)
        mx_records = dns_info.get('mx_records', [])
        if not mx_records:
            score += 15  # No email setup - suspicious for business sites
        elif len(mx_records) > 5:
            score += 10  # Excessive MX records - unusual

        # Check if domain has A records (basic DNS setup)
        a_records = dns_info.get('a_records', [])
        if not a_records:
            score += 40  # No A records - very suspicious
        elif len(a_records) > 8:
            score += 20  # Excessive A records - could be load balancing or suspicious
        elif len(a_records) > 3:
            score += 5   # Multiple A records - slightly unusual

        # Check for suspicious DNS patterns from domain_info
        suspicious_patterns = dns_info.get('suspicious_dns_patterns', [])
        score += len(suspicious_patterns) * 10

        # Check for private IP addresses
        for record in a_records:
            if record.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                                '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                                '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                                '172.30.', '172.31.', '192.168.', '127.')):
                score += 25
                break

        return min(score, 50)

    def _get_risk_level(self, score: float) -> str:
        """Convert numerical score to risk level with enhanced descriptions"""
        if score >= 90:
            return "🚨 CRITICAL RISK - Confirmed malicious site"
        elif score >= 75:
            return "🚨 HIGH RISK - Very likely malicious"
        elif score >= 60:
            return "⚠️ MEDIUM-HIGH RISK - Strong suspicion of malicious intent"
        elif score >= 45:
            return "⚠️ MEDIUM RISK - Multiple concerning indicators"
        elif score >= 30:
            return "🔶 LOW-MEDIUM RISK - Some suspicious factors"
        elif score >= 15:
            return "🔶 LOW RISK - Minor issues detected"
        elif score >= 5:
            return "✅ MOSTLY SAFE - Very minor concerns"
        else:
            return "✅ VERY SAFE - No significant issues detected"