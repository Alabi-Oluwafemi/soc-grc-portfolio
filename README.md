# SOC + GRC Portfolio

Aspiring SOC Analyst | GRC | Python for Security

This repo shows how I detect attacks in Python and document them like a GRC analyst.

## What I Built

### 1. SOC Detection Rules - `detection_rules.py`
Python functions that detect real attacks from logs:

- `check_impossible_travel()` - Detects CEO login from outside Nigeria = CRITICAL
- `check_brute_force()` - Detects 500 failed logins = HIGH, Block IP

**Concepts Used:** `if`, `and`, `dict`, `function`, `for`

### 2. GRC Incident Reports - `incident_report_ceo.md`
Professional incident report format:
Title, Severity, Summary, IOCs, Impact, Recommendation

**Example Incident:** CEO account compromise from Russia at 3:12 AM.
**IOC:** 185.220.101.4

## Skills Demonstrated
- IOC vs Event vs TTP
- Risk Assessment
- SIEM Detection Logic
- Incident Response: Block, Lock, Reset, Enforce MFA
- Python for SOC

## How To Run
```bash
python detection_rules.py
git init
git add .
git commit -m "Added SOC detection rules + GRC incident report"
git branch -M main
git remote add origin
https://github.com/Alabi-Oluwafemi/soc-grc-portfolio.git
git push -u origin main