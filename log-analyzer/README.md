# Project 4: SOC Log Analyzer

A mini-SIEM tool that analyzes server / firewall logs and detects attacks like a real SOC analyst would.

## What It Does
- Parses authentication logs
- Counts failed vs successful logins by IP
- Detects Brute Force Attacks (5+ failed logins from same IP)
- Detects Port Scans
- Detects Malware alerts
- Detects possible Account Compromise (many fails + then success)

## How To Run
```bash
python log_analyzer.py
