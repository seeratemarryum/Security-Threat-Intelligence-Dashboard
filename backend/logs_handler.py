import re
import pandas as pd
from datetime import datetime
import ipaddress
import json

class LogsHandler:
    def __init__(self):
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.common_attack_patterns = {
            'sql_injection': re.compile(r'(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\bdrop\b.*\btable\b)', re.IGNORECASE),
            'xss': re.compile(r'(<script>|javascript:|onload=|onerror=)', re.IGNORECASE),
            'path_traversal': re.compile(r'(\.\./|\.\.\\)', re.IGNORECASE),
            'command_injection': re.compile(r'(\bexec\b|\bsystem\b|\bpassthru\b|\bshell_exec\b)', re.IGNORECASE)
        }
    
    def process_log_file(self, file):
        """Process uploaded log file and extract security-relevant information"""
        try:
            content = file.read().decode('utf-8')
            lines = content.split('\n')
            
            processed_entries = []
            for line_num, line in enumerate(lines, 1):
                if line.strip():
                    ips = self._extract_ips(line)
                    attack_patterns = self._detect_attack_patterns(line)
                    
                    processed_entries.append({
                        'line_number': line_num,
                        'content': line.strip(),
                        'ip_addresses': ips,
                        'attack_patterns': attack_patterns,
                        'timestamp': datetime.now().isoformat(),
                        'severity': 'high' if attack_patterns else 'low'
                    })
            
            return processed_entries
            
        except Exception as e:
            raise Exception(f"Error processing log file: {str(e)}")
    
    def _extract_ips(self, text):
        """Extract and validate IP addresses from text"""
        ips = self.ip_pattern.findall(text)
        valid_ips = []
        
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                continue
        
        return valid_ips
    
    def _detect_attack_patterns(self, text):
        """Detect common web attack patterns in log entries"""
        detected_patterns = []
        
        for pattern_name, pattern in self.common_attack_patterns.items():
            if pattern.search(text):
                detected_patterns.append(pattern_name)
        
        return detected_patterns
    
    def cross_check_with_threat_intel(self, log_entries, abuseipdb_client, shodan_client=None):
        """Cross-check IPs from logs with threat intelligence"""
        threat_matches = []
        
        for entry in log_entries:
            for ip in entry['ip_addresses']:
                # Check with AbuseIPDB
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
                            'total_reports': abuse_result.get('totalReports', 0),
                            'last_reported': abuse_result.get('lastReportedAt', '')
                        }
                    })
                
                # Check with Shodan for additional context
                if shodan_client:
                    shodan_result = shodan_client.get_host_info(ip)
                    if shodan_result and shodan_result.get('vulnerabilities'):
                        threat_matches.append({
                            'log_entry': entry,
                            'ip_address': ip,
                            'threat_data': shodan_result,
                            'confidence_score': 80,
                            'severity': 'high',
                            'source': 'shodan',
                            'details': {
                                'vulnerabilities': shodan_result.get('vulnerabilities', []),
                                'ports': shodan_result.get('ports', []),
                                'organization': shodan_result.get('organization', 'Unknown')
                            }
                        })
        
        return threat_matches