from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_restful import Api, Resource
import os
from datetime import datetime
import json

# Import your existing modules
from config import Config
from api.shodan_client import ShodanClient
from api.abuseipdb_client import AbuseIPDBClient
from logs_handler import LogsHandler

app = Flask(__name__)
app.config.from_object(Config)
CORS(app)
api = Api(app)

# Initialize clients
shodan_client = ShodanClient()
abuseipdb_client = AbuseIPDBClient()
logs_handler = LogsHandler()

# Fallback test data in case APIs fail
def get_fallback_threat_data():
    """Provide test data when APIs are unavailable"""
    return [
        {
            'type': 'malicious_ip',
            'ip': '185.136.156.129',
            'abuse_confidence': 95,
            'country': 'Netherlands',
            'isp': 'IP Volume inc',
            'total_reports': 150,
            'severity': 'critical',
            'source': 'abuseipdb',
            'timestamp': datetime.now().isoformat()
        },
        {
            'type': 'malicious_ip', 
            'ip': '91.92.109.107',
            'abuse_confidence': 65,
            'country': 'Russia',
            'isp': 'OVH SAS',
            'total_reports': 25,
            'severity': 'medium',
            'source': 'abuseipdb',
            'timestamp': datetime.now().isoformat()
        },
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
            'timestamp': datetime.now().isoformat()
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
            'timestamp': datetime.now().isoformat()
        }
    ]

class ThreatIntelFeed(Resource):
    def get(self):
        try:
            # Try to get real data from APIs
            shodan_data = []
            abuseipdb_data = []
            
            # Get Shodan data
            try:
                if Config.SHODAN_API_KEY and Config.SHODAN_API_KEY != 'your_shodan_api_key_here':
                    shodan_data = shodan_client.search_vulnerable_hosts(limit=20)
                else:
                    print("Shodan API key not configured, using test data")
            except Exception as e:
                print(f"Shodan API error: {e}")
            
            # Get AbuseIPDB data
            try:
                if Config.ABUSEIPDB_API_KEY and Config.ABUSEIPDB_API_KEY != 'your_abuseipdb_api_key_here':
                    abuseipdb_data = abuseipdb_client.get_blacklist(limit=20)
                else:
                    print("AbuseIPDB API key not configured, using test data")
            except Exception as e:
                print(f"AbuseIPDB API error: {e}")
            
            # If no real data, use fallback
            if not shodan_data and not abuseipdb_data:
                all_threats = get_fallback_threat_data()
                source_counts = {'shodan': 2, 'abuseipdb': 2}  # Test data counts
            else:
                all_threats = shodan_data + abuseipdb_data
                source_counts = {
                    'shodan': len(shodan_data),
                    'abuseipdb': len(abuseipdb_data)
                }
            
            # Apply filters from request
            source_filter = request.args.get('source', 'all')
            severity_filter = request.args.get('severity', 'all')
            
            if source_filter != 'all':
                all_threats = [t for t in all_threats if t.get('source') == source_filter]
            
            if severity_filter != 'all':
                all_threats = [t for t in all_threats if t.get('severity') == severity_filter]
            
            return {
                'success': True,
                'data': all_threats,
                'count': len(all_threats),
                'sources': source_counts,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"Threat intelligence error: {e}")
            # Return test data on complete failure
            return {
                'success': True,
                'data': get_fallback_threat_data(),
                'count': 4,
                'sources': {'shodan': 2, 'abuseipdb': 2},
                'timestamp': datetime.now().isoformat(),
                'note': 'Using demonstration data'
            }

class LogUpload(Resource):
    def post(self):
        try:
            if 'file' not in request.files:
                return {'success': False, 'error': 'No file uploaded'}, 400
            
            file = request.files['file']
            if file.filename == '':
                return {'success': False, 'error': 'No file selected'}, 400
            
            # Process the uploaded log file
            results = logs_handler.process_log_file(file)
            
            # Cross-check with threat intelligence
            cross_check_results = logs_handler.cross_check_with_threat_intel(
                results, 
                abuseipdb_client
            )
            
            # Generate security report
            security_report = logs_handler.generate_security_report(results, cross_check_results)
            
            return {
                'success': True,
                'filename': file.filename,
                'processed_entries': len(results),
                'threat_matches': len(cross_check_results),
                'matches': cross_check_results,
                'security_report': security_report,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}, 500

class IPCheck(Resource):
    def get(self, ip_address):
        try:
            # Validate IP format
            import ipaddress
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                return {'success': False, 'error': 'Invalid IP address format'}, 400
            
            abuse_result = None
            shodan_result = None
            
            # Get AbuseIPDB data if available
            if Config.ABUSEIPDB_API_KEY and Config.ABUSEIPDB_API_KEY != 'your_abuseipdb_api_key_here':
                abuse_result = abuseipdb_client.check_ip(ip_address)
            
            # Get Shodan data if available  
            if Config.SHODAN_API_KEY and Config.SHODAN_API_KEY != 'your_shodan_api_key_here':
                shodan_result = shodan_client.get_host_info(ip_address)
            
            response_data = {
                'ip': ip_address,
                'abuseipdb': abuse_result,
                'shodan': shodan_result,
                'overall_risk': 'unknown'
            }
            
            # Calculate overall risk
            risks = []
            if abuse_result and abuse_result.get('abuseConfidenceScore', 0) > 50:
                risks.append('malicious_ip')
            if shodan_result and shodan_result.get('vulnerabilities'):
                risks.append('vulnerable_service')
            
            if 'malicious_ip' in risks and abuse_result.get('abuseConfidenceScore', 0) > 75:
                response_data['overall_risk'] = 'critical'
            elif 'malicious_ip' in risks or 'vulnerable_service' in risks:
                response_data['overall_risk'] = 'high'
            elif abuse_result and abuse_result.get('abuseConfidenceScore', 0) > 25:
                response_data['overall_risk'] = 'medium'
            else:
                response_data['overall_risk'] = 'low'
            
            return {'success': True, 'data': response_data}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}, 500

class Stats(Resource):
    def get(self):
        try:
            # Get threat data
            threat_response = ThreatIntelFeed().get()
            if threat_response[1] == 200:  # Check if it's an error response
                threat_data = threat_response[0]['data']
            else:
                threat_data = threat_response['data']
            
            # Calculate statistics
            stats = {
                'total_threats': len(threat_data),
                'by_source': {
                    'shodan': len([t for t in threat_data if t.get('source') == 'shodan']),
                    'abuseipdb': len([t for t in threat_data if t.get('source') == 'abuseipdb'])
                },
                'by_severity': {
                    'critical': len([t for t in threat_data if t.get('severity') == 'critical']),
                    'high': len([t for t in threat_data if t.get('severity') == 'high']),
                    'medium': len([t for t in threat_data if t.get('severity') == 'medium']),
                    'low': len([t for t in threat_data if t.get('severity') == 'low'])
                },
                'by_country': {},
                'recent_threats': threat_data[:5]  # Last 5 threats
            }
            
            # Calculate country distribution
            for threat in threat_data:
                country = threat.get('country', 'Unknown')
                stats['by_country'][country] = stats['by_country'].get(country, 0) + 1
            
            return {'success': True, 'stats': stats}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}, 500

# Register API endpoints
api.add_resource(ThreatIntelFeed, '/api/threat-intel')
api.add_resource(LogUpload, '/api/upload-logs')
api.add_resource(IPCheck, '/api/check-ip/<string:ip_address>')
api.add_resource(Stats, '/api/stats')

@app.route('/api/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'services': {
            'shodan': 'available' if Config.SHODAN_API_KEY and Config.SHODAN_API_KEY != 'your_shodan_api_key_here' else 'test_data',
            'abuseipdb': 'available' if Config.ABUSEIPDB_API_KEY and Config.ABUSEIPDB_API_KEY != 'your_abuseipdb_api_key_here' else 'test_data'
        }
    })

@app.route('/')
def home():
    return jsonify({
        'message': 'Security Dashboard API is running!',
        'endpoints': {
            'threat_intel': '/api/threat-intel',
            'upload_logs': '/api/upload-logs',
            'check_ip': '/api/check-ip/<ip>',
            'stats': '/api/stats',
            'health': '/api/health'
        }
    })

if __name__ == '__main__':
    if not os.path.exists('static/uploads'):
        os.makedirs('static/uploads')
    
    print("🚀 Security Dashboard Backend Starting...")
    print("📍 Endpoints:")
    print("   GET  /api/threat-intel     - Threat intelligence feed")
    print("   POST /api/upload-logs      - Upload and analyze logs") 
    print("   GET  /api/check-ip/<ip>    - Check IP reputation")
    print("   GET  /api/stats            - Get statistics")
    print("   GET  /api/health           - Health check")
    print("\n📊 Frontend: http://localhost:3000")
    print("🔧 Backend:  http://localhost:5000")
    print("\n⚡ Server starting on http://localhost:5000")
    
    app.run(debug=True, host='0.0.0.0', port=5000)