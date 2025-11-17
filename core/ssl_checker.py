"""
SSL Certificate Analysis
Check SSL certificate validity and security
"""

import ssl
import socket
from datetime import datetime
from typing import Dict, Any


class SSLChecker:
    def check_ssl_certificate(self, domain: str) -> Dict[str, Any]:
        """Analyze SSL certificate"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    # Parse certificate info
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days

                    return {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'not_after': not_after,
                        'not_before': not_before,
                        'days_until_expiry': days_until_expiry,
                        'is_valid': days_until_expiry > 0,
                        'version': ssock.version()
                    }
        except Exception as e:
            return {'error': str(e)}