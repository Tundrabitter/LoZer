import unittest
from analyzer import LogAnalyzer  # Import your class
class TestLogAnalyzer(unittest.TestCase):

    def test_brute_force_detection(self):
        # This test checks if the script correctly identifies multiple failed logins from a single IP.
        analyzer = LogAnalyzer("sample_logs/access.log")
        analyzer.analyze()
        # Check if the suspicious_activities list contains a 'BRUTE_FORCE' alert for IP 192.168.1.101
        found_brute_force = any(alert['type'] == 'BRUTE_FORCE' and alert['ip'] == '192.168.1.101' for alert in analyzer.stats['suspicious_activities'])
        self.assertTrue(found_brute_force, "Brute force attack was not detected")

    def test_sql_injection_detection(self):
        # This test checks if the script flags a common SQL injection pattern.
        analyzer = LogAnalyzer("sample_logs/access.log")
        analyzer.analyze()
        # Check if an alert was generated for the SQL injection attempt IP
        found_sqli = any('SQL' in alert['type'] for alert in analyzer.stats['suspicious_activities'])
        self.assertTrue(found_sqli, "SQL injection attempt was not detected")

    # You can add more test methods for directory traversal, scanner detection, etc.

if __name__ == '__main__':
    unittest.main()