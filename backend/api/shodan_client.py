import shodan
from config import Config

class ShodanClient:
    def __init__(self):
        self.api = shodan.Shodan(Config.SHODAN_API_KEY)
    
    def search_vulnerable_hosts(self, query='vuln:cve', limit=50):
        try:
            results = self.api.search(query, limit=limit)
            normalized_results = []
            
            for result in results['matches']:
                normalized_results.append({
                    'type': 'vulnerable_service',
                    'ip': result['ip_str'],
                    'port': result.get('port', 'N/A'),
                    'organization': result.get('org', 'Unknown'),
                    'hostnames': result.get('hostnames', []),
                    'vulnerabilities': result.get('vulns', []),
                    'product': result.get('product', 'Unknown'),
                    'version': result.get('version', 'Unknown'),
                    'severity': 'high' if result.get('vulns') else 'medium',
                    'source': 'shodan',
                    'timestamp': result.get('timestamp', ''),
                    'country': result.get('location', {}).get('country_name', 'Unknown'),
                    'data': result.get('data', '')[:200]  # First 200 chars of banner
                })
            
            return normalized_results
        except shodan.APIError as e:
            print(f"Shodan API error: {e}")
            return []
        except Exception as e:
            print(f"Shodan error: {e}")
            return []
    
    def get_host_info(self, ip_address):
        """Get detailed information about a specific host"""
        try:
            host = self.api.host(ip_address)
            
            return {
                'ip': host['ip_str'],
                'country': host.get('country_name', 'Unknown'),
                'city': host.get('city', 'Unknown'),
                'organization': host.get('org', 'Unknown'),
                'operating_system': host.get('os', 'Unknown'),
                'ports': host.get('ports', []),
                'vulnerabilities': host.get('vulns', []),
                'last_update': host.get('last_update', ''),
                'data': [data.get('data', '') for data in host.get('data', [])]
            }
        except shodan.APIError as e:
            print(f"Shodan host info error: {e}")
            return None
        except Exception as e:
            print(f"Shodan host error: {e}")
            return None
    
    def search_services(self, service_query, limit=25):
        """Search for specific services"""
        try:
            results = self.api.search(service_query, limit=limit)
            services = []
            
            for result in results['matches']:
                services.append({
                    'ip': result['ip_str'],
                    'port': result.get('port'),
                    'service': result.get('product', 'Unknown'),
                    'version': result.get('version', 'Unknown'),
                    'banner': result.get('data', '')[:150],
                    'organization': result.get('org', 'Unknown'),
                    'country': result.get('location', {}).get('country_name', 'Unknown')
                })
            
            return services
        except Exception as e:
            print(f"Shodan service search error: {e}")
            return []