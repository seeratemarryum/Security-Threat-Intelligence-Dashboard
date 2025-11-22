class AbuseIPDBClient:
    def __init__(self):
        self.api_key = 'your_abuseipdb_api_key_here'
    
    def get_blacklist(self, limit=25):
        return self._get_test_data()
    
    def check_ip(self, ip_address):
        return {
            'ipAddress': ip_address,
            'abuseConfidenceScore': 85,
            'countryCode': 'US',
            'isp': 'Test ISP',
            'totalReports': 25
        }
    
    def _get_test_data(self):
        return [
            {
                'type': 'malicious_ip',
                'ip': '185.136.156.129',
                'abuse_confidence': 95,
                'country': 'Netherlands',
                'isp': 'IP Volume inc',
                'total_reports': 150,
                'severity': 'critical',
                'source': 'abuseipdb'
            },
            {
                'type': 'malicious_ip', 
                'ip': '91.92.109.107',
                'abuse_confidence': 65,
                'country': 'Russia',
                'isp': 'OVH SAS',
                'total_reports': 25,
                'severity': 'medium',
                'source': 'abuseipdb'
            },
            {
                'type': 'malicious_ip',
                'ip': '103.106.189.100',
                'abuse_confidence': 80,
                'country': 'China',
                'isp': 'China Telecom',
                'total_reports': 80,
                'severity': 'high',
                'source': 'abuseipdb'
            }
        ]