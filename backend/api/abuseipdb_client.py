import requests
from config import Config

class AbuseIPDBClient:
    def __init__(self):
        self.api_key = Config.ABUSEIPDB_API_KEY
        self.base_url = 'https://api.abuseipdb.com/api/v2'
    
    def get_blacklist(self, limit=50):
        headers = {
            'Key': self.api_key,
            'Accept': 'application/json'
        }
        
        params = {
            'limit': limit,
            'confidenceMinimum': 80
        }
        
        try:
            response = requests.get(
                f'{self.base_url}/blacklist',
                headers=headers,
                params=params
            )
            
            if response.status_code == 200:
                data = response.json()
                normalized_results = []
                
                for entry in data.get('data', []):
                    normalized_results.append({
                        'type': 'malicious_ip',
                        'ip': entry['ipAddress'],
                        'abuse_confidence': entry['abuseConfidenceScore'],
                        'country': entry.get('countryCode', 'Unknown'),
                        'isp': entry.get('isp', 'Unknown'),
                        'domain': entry.get('domain', 'Unknown'),
                        'total_reports': entry.get('totalReports', 0),
                        'last_reported': entry.get('lastReportedAt', ''),
                        'severity': self._calculate_severity(entry['abuseConfidenceScore']),
                        'source': 'abuseipdb'
                    })
                
                return normalized_results
            else:
                print(f"AbuseIPDB API error: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            print(f"AbuseIPDB error: {e}")
            return []
    
    def _calculate_severity(self, confidence_score):
        if confidence_score >= 90:
            return 'critical'
        elif confidence_score >= 75:
            return 'high'
        elif confidence_score >= 50:
            return 'medium'
        else:
            return 'low'
    
    def check_ip(self, ip_address):
        headers = {
            'Key': self.api_key,
            'Accept': 'application/json'
        }
        
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90
        }
        
        try:
            response = requests.get(
                f'{self.base_url}/check',
                headers=headers,
                params=params
            )
            
            if response.status_code == 200:
                return response.json()['data']
            else:
                print(f"AbuseIPDB check error: {response.status_code}")
                return None
        except Exception as e:
            print(f"AbuseIPDB check error: {e}")
            return None
    
    def report_ip(self, ip_address, categories, comment=""):
        """Report an IP address to AbuseIPDB"""
        headers = {
            'Key': self.api_key,
            'Accept': 'application/json'
        }
        
        data = {
            'ip': ip_address,
            'categories': categories,  # Comma-separated category IDs
            'comment': comment
        }
        
        try:
            response = requests.post(
                f'{self.base_url}/report',
                headers=headers,
                data=data
            )
            
            if response.status_code == 200:
                return {'success': True, 'data': response.json()}
            else:
                return {'success': False, 'error': response.text}
        except Exception as e:
            return {'success': False, 'error': str(e)}