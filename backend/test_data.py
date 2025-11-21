import json
from datetime import datetime, timedelta

def generate_sample_threats():
    """Generate realistic sample threat data for testing"""
    sample_threats = [
        # Critical threats from AbuseIPDB
        {
            'type': 'malicious_ip',
            'ip': '185.136.156.129',
            'abuse_confidence': 95,
            'country': 'Netherlands',
            'isp': 'IP Volume inc',
            'domain': 'malicious-domain.com',
            'total_reports': 150,
            'last_reported': (datetime.now() - timedelta(days=1)).isoformat(),
            'severity': 'critical',
            'source': 'abuseipdb',
            'timestamp': datetime.now().isoformat()
        },
        {
            'type': 'malicious_ip',
            'ip': '91.92.109.107', 
            'abuse_confidence': 87,
            'country': 'Russia',
            'isp': 'OVH SAS',
            'domain': 'suspicious-host.net',
            'total_reports': 89,
            'last_reported': (datetime.now() - timedelta(days=2)).isoformat(),
            'severity': 'high',
            'source': 'abuseipdb',
            'timestamp': datetime.now().isoformat()
        },
        # High threats from Shodan
        {
            'type': 'vulnerable_service',
            'ip': '45.33.32.156',
            'port': 22,
            'organization': 'Linode LLC',
            'hostnames': ['vulnerable-server.com'],
            'vulnerabilities': ['CVE-2020-15778', 'CVE-2018-15473'],
            'product': 'OpenSSH',
            'version': '7.4',
            'severity': 'high',
            'source': 'shodan',
            'country': 'United States',
            'timestamp': datetime.now().isoformat(),
            'data': 'SSH-2.0-OpenSSH_7.4'
        },
        {
            'type': 'vulnerable_service',
            'ip': '203.0.113.45',
            'port': 80,
            'organization': 'Compromised Hosting',
            'hostnames': ['old-wordpress-site.com'],
            'vulnerabilities': ['CVE-2019-9769'],
            'product': 'Apache',
            'version': '2.4.29',
            'severity': 'medium',
            'source': 'shodan', 
            'country': 'Germany',
            'timestamp': datetime.now().isoformat(),
            'data': 'Apache/2.4.29 (Ubuntu)'
        },
        # Low threat examples
        {
            'type': 'malicious_ip',
            'ip': '192.0.78.123',
            'abuse_confidence': 45,
            'country': 'United States',
            'isp': 'Cloudflare Inc',
            'domain': 'legitimate-but-reported.com',
            'total_reports': 12,
            'last_reported': (datetime.now() - timedelta(days=30)).isoformat(),
            'severity': 'low',
            'source': 'abuseipdb',
            'timestamp': datetime.now().isoformat()
        },
        {
            'type': 'vulnerable_service',
            'ip': '8.8.8.8',
            'port': 53,
            'organization': 'Google LLC',
            'hostnames': ['dns.google'],
            'vulnerabilities': [],
            'product': 'DNS',
            'version': 'Unknown',
            'severity': 'low',
            'source': 'shodan',
            'country': 'United States',
            'timestamp': datetime.now().isoformat(),
            'data': 'DNS server response'
        }
    ]
    return sample_threats

if __name__ == '__main__':
    threats = generate_sample_threats()
    print(f"Generated {len(threats)} sample threats")
    for threat in threats:
        print(f"- {threat['ip']} ({threat['severity']}) - {threat['source']}")