#!/usr/bin/env python3
"""
Simple Log Analysis Script for Cybersecurity
Author: Tundrabitter
Purpose: Detect suspicious activity in web server
"""

import re
import argparse
from collections import defaultdict, Counter
from datetime import datetime
import sys

class LogAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.suspicious_ips = defaultdict(list)
        self.stats = {
            'total_requests': 0,
            'failed_logins': 0,
            'unique_ips': set(),
            'suspicious_activities': []
        }
    
    def parse_log_line(self, line):
        """Parse a single log line using regex - IMPROVED VERSION"""
        patterns = [
            # Pattern with timezone: 192.168.1.100 - - [25/Dec/2023:10:15:32 +0000] "GET /login HTTP/1.1" 200 512
            r'(\d+\.\d+\.\d+\.\d+) - - \[(.*? \+\d+)\] "(.*?)" (\d+) (\d+)',
            # Pattern without timezone (fallback): 192.168.1.100 - - [25/Dec/2023:10:15:32] "GET /login HTTP/1.1" 200 512
            r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)',
            # Pattern that handles hyphens in size field (some logs use '-' for zero size)
            r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d+) (-)'
        ]
        
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                ip, timestamp, request, status, size = match.groups()
                # Handle the size field whether it's a number or hyphen
                size_value = 0 if size == '-' else int(size)
                return {
                    'ip': ip,
                    'timestamp': timestamp,
                    'request': request,
                    'status': int(status),
                    'size': size_value
                }
        
        # If no pattern matches, print a warning (optional - helps with debugging)
        print(f"Warning: Could not parse line: {line.strip()}")
        return None
    
    def detect_brute_force(self, log_entry, threshold=5):
        """Detect multiple failed login attempts from same IP"""
        if log_entry['status'] in [401, 403]:  # Unauthorized/Forbidden
            ip = log_entry['ip']
            self.suspicious_ips[ip].append(log_entry)
            
            # Check if this IP has exceeded the threshold
            if len(self.suspicious_ips[ip]) >= threshold:
                # Avoid duplicate alerts
                if not any(alert['ip'] == ip and alert['type'] == 'BRUTE_FORCE' 
                          for alert in self.stats['suspicious_activities']):
                    self.stats['suspicious_activities'].append({
                        'type': 'BRUTE_FORCE',
                        'ip': ip,
                        'attempts': len(self.suspicious_ips[ip]),
                        'last_attempt': log_entry['timestamp'],
                        'description': f'Multiple failed login attempts ({len(self.suspicious_ips[ip])}) from same IP'
                    })

    def detect_directory_traversal(self, log_entry):
        """Detect potential directory traversal attacks"""
        suspicious_patterns = ['../', '/etc/passwd', '/bin/', 'cmd.exe', '/etc/shadow']
        request = log_entry.get('request', '')
        
        for pattern in suspicious_patterns:
            if pattern in request:
                # Avoid duplicate alerts
                if not any(alert['ip'] == log_entry['ip'] and alert['type'] == 'DIRECTORY_TRAVERSAL' 
                          for alert in self.stats['suspicious_activities']):
                    self.stats['suspicious_activities'].append({
                        'type': 'DIRECTORY_TRAVERSAL',
                        'ip': log_entry['ip'],
                        'pattern': pattern,
                        'request': request,
                        'timestamp': log_entry['timestamp'],
                        'description': f'Directory traversal attempt detected: {pattern}'
                    })
                return True
        return False

    def detect_sql_injection(self, log_entry):
        """Detect potential SQL injection attempts"""
        sql_patterns = ["' OR '1'='1", "' OR 1=1", "UNION SELECT", "DROP TABLE", "SELECT * FROM"]
        request = log_entry.get('request', '')
        
        for pattern in sql_patterns:
            if pattern in request.upper():  # Case insensitive check
                # Avoid duplicate alerts
                if not any(alert['ip'] == log_entry['ip'] and alert['type'] == 'SQL_INJECTION' 
                          for alert in self.stats['suspicious_activities']):
                    self.stats['suspicious_activities'].append({
                        'type': 'SQL_INJECTION',
                        'ip': log_entry['ip'],
                        'pattern': pattern,
                        'request': request,
                        'timestamp': log_entry['timestamp'],
                        'description': f'SQL injection attempt detected: {pattern}'
                    })
                return True
        return False

    def analyze(self):
        """Main analysis function"""
        try:
            with open(self.log_file, 'r') as file:
                for line_num, line in enumerate(file, 1):
                    self.stats['total_requests'] += 1
                    
                    log_entry = self.parse_log_line(line)
                    if log_entry:
                        self.stats['unique_ips'].add(log_entry['ip'])
                        
                        # Check for failed logins and other attacks
                        if log_entry['status'] in [401, 403]:
                            self.stats['failed_logins'] += 1
                            self.detect_brute_force(log_entry)
                        
                        # Check for other attack patterns (for ALL requests)
                        self.detect_directory_traversal(log_entry)
                        self.detect_sql_injection(log_entry)
                    
                    # Progress indicator
                    if line_num % 1000 == 0:
                        print(f"Processed {line_num} lines...")
                        
        except FileNotFoundError:
            print(f"Error: Log file '{self.log_file}' not found.")
            return False
            
        return True
    
    def generate_report(self):
        """Generate a security report"""
        print("\n" + "="*50)
        print("SECURITY ANALYSIS REPORT")
        print("="*50)
        
        print(f"\nBasic Statistics:")
        print(f"- Total requests: {self.stats['total_requests']}")
        print(f"- Unique IP addresses: {len(self.stats['unique_ips'])}")
        print(f"- Failed login attempts: {self.stats['failed_logins']}")
        
        print(f"\nSuspicious Activities Found: {len(self.stats['suspicious_activities'])}")
        
        for activity in self.stats['suspicious_activities']:
            print(f"\n⚠️  ALERT: {activity['type']}")
            print(f"   IP: {activity['ip']}")
            if 'attempts' in activity:
                print(f"   Attempts: {activity['attempts']}")
            if 'pattern' in activity:
                print(f"   Pattern: {activity['pattern']}")
            if 'description' in activity:
                print(f"   Description: {activity['description']}")
        
        if not self.stats['suspicious_activities']:
            print("✅ No critical threats detected")

def main():
    parser = argparse.ArgumentParser(description='Log Analysis Tool for Security Monitoring')
    parser.add_argument('logfile', help='Path to the log file to analyze')
    parser.add_argument('--threshold', type=int, default=5, 
                       help='Failed login threshold for alerts (default: 5)')
    
    args = parser.parse_args()
    
    print(f"Analyzing log file: {args.logfile}")
    
    analyzer = LogAnalyzer(args.logfile)
    
    if analyzer.analyze():
        analyzer.generate_report()
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()