from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_restful import Api, Resource
import os
from datetime import datetime
import json
from config import Config
from api.shodan_client import ShodanClient
from api.abuseipdb_client import AbuseIPDBClient

app = Flask(__name__)
app.config.from_object(Config)
CORS(app)
api = Api(app)

# Initialize clients
shodan_client = ShodanClient()
abuseipdb_client = AbuseIPDBClient()

class LogsHandler:
    def __init__(self):
        import re
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    
    def process_log_file(self, file):
        try:
            content = file.read().decode('utf-8')
            lines = content.split('\n')
            
            processed_entries = []
            for line_num, line in enumerate(lines, 1):
                if line.strip():
                    ips = self._extract_ips(line)
                    
                    processed_entries.append({
                        'line_number': line_num,
                        'content': line.strip(),
                        'ip_addresses': ips,
                        'timestamp': datetime.now().isoformat()
                    })
            
            return processed_entries
        except Exception as e:
            raise Exception(f"Error processing log file: {str(e)}")
    
    def _extract_ips(self, text):
        import ipaddress
        ips = self.ip_pattern.findall(text)
        valid_ips = []
        
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                continue
        return valid_ips
    
    def cross_check_with_threat_intel(self, log_entries, abuseipdb_client, shodan_client=None):
        threat_matches = []
        
        for entry in log_entries:
            for ip in entry['ip_addresses']:
                abuse_result = abuseipdb_client.check_ip(ip)
                
                if abuse_result and abuse_result.get('abuseConfidenceScore', 0) > 50:
                    threat_matches.append({
                        'log_entry': entry,
                        'ip_address': ip,
                        'threat_data': abuse_result,
                        'confidence_score': abuse_result.get('abuseConfidenceScore', 0),
                        'severity': 'high' if abuse_result.get('abuseConfidenceScore', 0) > 75 else 'medium',
                        'source': 'abuseipdb',
                        'details': {
                            'isp': abuse_result.get('isp', 'Unknown'),
                            'country': abuse_result.get('countryCode', 'Unknown'),
                            'total_reports': abuse_result.get('totalReports', 0)
                        }
                    })
        return threat_matches

logs_handler = LogsHandler()

class ThreatIntelFeed(Resource):
    def get(self):
        try:
            shodan_data = shodan_client.search_vulnerable_hosts(limit=20)
            abuseipdb_data = abuseipdb_client.get_blacklist(limit=20)
            
            all_threats = shodan_data + abuseipdb_data
            
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
                'sources': {
                    'shodan': len(shodan_data),
                    'abuseipdb': len(abuseipdb_data)
                },
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'data': [],
                'timestamp': datetime.now().isoformat()
            }

class LogUpload(Resource):
    def post(self):
        try:
            if 'file' not in request.files:
                return {'success': False, 'error': 'No file uploaded'}, 400
            
            file = request.files['file']
            if file.filename == '':
                return {'success': False, 'error': 'No file selected'}, 400
            
            results = logs_handler.process_log_file(file)
            cross_check_results = logs_handler.cross_check_with_threat_intel(results, abuseipdb_client, shodan_client)
            
            return {
                'success': True,
                'filename': file.filename,
                'processed_entries': len(results),
                'threat_matches': len(cross_check_results),
                'matches': cross_check_results,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}, 500

class Stats(Resource):
    def get(self):
        try:
            threat_response = ThreatIntelFeed().get()
            threat_data = threat_response[0]['data'] if isinstance(threat_response, tuple) else threat_response['data']
            
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
            }
            
            for threat in threat_data:
                country = threat.get('country', 'Unknown')
                stats['by_country'][country] = stats['by_country'].get(country, 0) + 1
            
            return {'success': True, 'stats': stats}
        except Exception as e:
            return {'success': False, 'error': str(e)}, 500

# Register API endpoints
api.add_resource(ThreatIntelFeed, '/api/threat-intel')
api.add_resource(LogUpload, '/api/upload-logs')
api.add_resource(Stats, '/api/stats')

@app.route('/api/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route('/')
def home():
    return jsonify({
        'message': 'Security Dashboard API is running!',
        'endpoints': {
            'threat_intel': '/api/threat-intel',
            'upload_logs': '/api/upload-logs',
            'stats': '/api/stats',
            'health': '/api/health'
        }
    })

if __name__ == '__main__':
    print("🚀 Security Dashboard Backend Starting...")
    print("📍 Available Endpoints:")
    print("   GET  /api/threat-intel     - Threat intelligence feed")
    print("   POST /api/upload-logs      - Upload and analyze logs") 
    print("   GET  /api/stats            - Get statistics")
    print("   GET  /api/health           - Health check")
    print("\n📊 Frontend: http://localhost:3000")
    print("🔧 Backend:  http://localhost:5000")
    
    app.run(debug=True, host='0.0.0.0', port=5000)