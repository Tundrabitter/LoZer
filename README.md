# LoZer - Cybersecurity Log Analysis Tool

Python tool for detecting security threats in web server logs

## Usage
- Ensure you have Python installed (preferably Python 3.6 or above)
- The main script is analyzer.py
- The tool can be run from the command line, passing the path to the log file as an argument
- python3 analyzer.py /path/to/your/logfile.log
- The tool will then analyze the log file and print a security report
- Additionally, the user can generate sample logs using generate_logs.py for testing

## How do I get a logfile?

- From a web server (like Apache or Nginx):
- Apache: Typically found in /var/log/apache2/access.log (or /var/log/httpd/access_log)
- Nginx: Typically found in /var/log/nginx/access.log
- You can also use the provided generate_logs.py script to create sample logs for testing
- If you have a live website, you can configure the web server to log in the required format
- For testing, you can also use existing log files from public datasets (like those from the SECURITY LAB or other sources)

The LoZer tool expects logs in a format similar to the Common Log Format, but with the timezone offset (like +0000) in the timestamp. Specifically, the regex in the LoZer tool (parse_log_line method) expects:
- IP address
- Timestamp in the format [day/month/year:hour:minute:second timezone]
- Request method, URL, and protocol (inside double quotes)
- Status code
- Response size (or '-' for empty)

## Features
- Brute force attack detection
- SQL injection detection  
- Directory traversal detection
- Security reporting

## Installation
- git clone https://github.com/Tundrabitter/LoZer.git
- cd LoZer
- python3 -m venv venv
- source venv/bin/activate
- pip install faker

## Project Structure
- analyzer.py - Main analysis script
- generate_logs.py - Log generation utility  
- test_analyzer.py - Unit tests
- sample_logs/ - Sample log files

## Legal Notice
For educational purposes and authorized security testing only.
