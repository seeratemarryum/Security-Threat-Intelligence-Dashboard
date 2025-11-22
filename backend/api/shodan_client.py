class ShodanClient:
    def __init__(self):
        self.api_key = 'your_shodan_api_key_here'
    
    def search_vulnerable_hosts(self, query='vuln:cve', limit=25):
        return self._get_test_data()
    
    def get_host_info(self, ip_address):
        return None
    
    def _get_test_data(self):
        return [
            {
                'type': 'vulnerable_service',
                'ip': '45.33.32.156',
                'port': 22,
                'organization': 'Linode LLC',
                'product': 'OpenSSH',
                'version': '7.4',
                'vulnerabilities': ['CVE-2020-15778'],
                'severity': 'high',
                'source': 'shodan',
                'country': 'United States',
                'timestamp': '2024-01-15T10:30:00Z'
            },
            {
                'type': 'vulnerable_service',
                'ip': '8.8.8.8',
                'port': 53,
                'organization': 'Google LLC',
                'product': 'DNS',
                'version': 'Unknown',
                'vulnerabilities': [],
                'severity': 'low',
                'source': 'shodan', 
                'country': 'United States',
                'timestamp': '2024-01-15T10:25:00Z'
            },
            {
                'type': 'vulnerable_service',
                'ip': '192.168.1.1',
                'port': 80,
                'organization': 'Test Corp',
                'product': 'Apache',
                'version': '2.4',
                'vulnerabilities': ['CVE-2021-41773'],
                'severity': 'critical',
                'source': 'shodan',
                'country': 'Germany',
                'timestamp': '2024-01-15T10:20:00Z'
            }
        ]