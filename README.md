# LoZer - Cybersecurity Log Analysis Tool

Python tool for detecting security threats in web server logs.

## Usage
python analyzer.py sample_logs/access.log

## Features
- Brute force attack detection
- SQL injection detection  
- Directory traversal detection
- Security reporting

## Installation
git clone https://github.com/Tundrabitter/LoZer.git
cd LoZer
python3 -m venv venv
source venv/bin/activate
pip install faker

## Project Structure
- analyzer.py - Main analysis script
- generate_logs.py - Log generation utility  
- test_analyzer.py - Unit tests
- sample_logs/ - Sample log files

## Legal Notice
For educational purposes and authorized security testing only.
