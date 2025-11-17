"""
Domain Information Module
WHOIS lookup and DNS record analysis
"""

import whois
import dns.resolver
from typing import Dict, Any


class DomainInfo:
    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information for domain"""
        try:
            domain_info = whois.whois(domain)
            return {
                'registrar': domain_info.registrar,
                'creation_date': domain_info.creation_date,
                'expiration_date': domain_info.expiration_date,
                'name_servers': domain_info.name_servers,
                'status': domain_info.status
            }
        except Exception as e:
            return {'error': str(e)}

    def get_dns_records(self, domain: str) -> Dict[str, Any]:
        """Get DNS records for domain with enhanced analysis"""
        records = {}
        suspicious_patterns = []

        try:
            # A records
            a_records = dns.resolver.resolve(domain, 'A')
            records['a_records'] = [str(r) for r in a_records]

            # Check for suspicious IP patterns
            for ip in records['a_records']:
                if ip.startswith(('10.', '172.16.', '192.168.', '127.')):
                    suspicious_patterns.append(f"Private IP address: {ip}")
                elif ip.startswith('0.'):
                    suspicious_patterns.append(f"Invalid IP range: {ip}")

        except:
            records['a_records'] = []
            suspicious_patterns.append("No A records found")

        try:
            # MX records
            mx_records = dns.resolver.resolve(domain, 'MX')
            records['mx_records'] = [str(r) for r in mx_records]
        except:
            records['mx_records'] = []
            suspicious_patterns.append("No MX records (uncommon for legitimate sites)")

        try:
            # TXT records (often used for verification)
            txt_records = dns.resolver.resolve(domain, 'TXT')
            records['txt_records'] = [str(r) for r in txt_records]
        except:
            records['txt_records'] = []

        records['suspicious_dns_patterns'] = suspicious_patterns

        return records