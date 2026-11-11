# Phishing Email Analyzer - SOC L1 Triage Tool

Python tool to analyze suspicious emails for phishing indicators and help SOC Analysts decide: Block, Quarantine, or Release?

Built by **Oluwafemi Alabi** | Lead Analyst at Riley Consultech Solutions Ltd | SOC | GRC

## What It Detects

- **Spoofed Senders** - Free email (gmail/yahoo) claiming to be CEO/Bank
- **Urgency / Social Engineering** - "Urgent", "Account Suspended", "Verify Now"
- **Malicious URLs** - IP-based URLs, suspicious TLDs (.tk, .xyz), @ tricks, URL shorteners, typosquatting
- **Dangerous Attachments** - .exe, .scr, .zip, .iso mentions

## How To Run

```bash
python phishing_analyzer.py