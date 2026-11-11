"""
Phishing Email Analyzer - SOC L1 Triage Tool
Author: Oluwafemi Alabi - Lead Analyst, Riley Consultech Solutions Ltd
Use: Analyze suspicious emails for phishing indicators and generate a SOC report
"""

import re
from urllib.parse import urlparse
from datetime import datetime

# --- Phishing Indicators ---
URGENCY_KEYWORDS = [
    "urgent", "immediate action", "verify now", "account suspended",
    "password expired", "click here", "confirm your account",
    "wire transfer", "invoice overdue", "action required"
]

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz"]
FREE_SENDERS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]

def extract_urls(text):
    """Extract all URLs from email body"""
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_pattern, text)

def check_url(url):
    """Check a single URL for phishing signs"""
    reasons = []
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc.lower()
        
        # IP address instead of domain
        if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
            reasons.append("URL uses IP address instead of domain name")
        
        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                reasons.append(f"Suspicious TLD: {tld}")
        
        # @ symbol trick - hides real domain
        if "@" in url:
            reasons.append("URL contains '@' - possible domain hiding trick")
        
        # Too many subdomains
        if domain.count(".") > 3:
            reasons.append("Excessive subdomains - possible typosquatting")
        
        # URL shortener
        if any(s in domain for s in ["bit.ly", "tinyurl", "t.co", "goo.gl"]):
            reasons.append("URL shortener hides final destination")
            
    except Exception as e:
        reasons.append(f"Could not parse URL: {e}")
    
    return reasons

def analyze_email(sender, subject, body, headers=""):
    """Main analysis function - returns score and report"""
    score = 0
    findings = []
    
    print(f"\n{'='*60}")
    print(f"PHISHING EMAIL ANALYSIS REPORT")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Analyst: Oluwafemi Alabi")
    print(f"{'='*60}")
    
    # 1. Sender Check
    print(f"\n[1] SENDER: {sender}")
    sender_domain = sender.split("@")[-1].lower() if "@" in sender else "unknown"
    if sender_domain in FREE_SENDERS and "bank" in subject.lower() or "ceo" in subject.lower():
        findings.append("Free email provider claiming to be corporate/bank")
        score += 25
        print("  [!] Free sender claiming to be corporate - HIGH RISK")
    
    # Display name spoofing check
    if "<" in sender and ">" in sender:
        display_name = sender.split("<")[0].strip()
        print(f"  Display Name: {display_name}")
        print(f"  Actual Address: {sender.split('<')[1].replace('>','')}")
    
    # 2. Subject / Urgency Check
    print(f"\n[2] SUBJECT: {subject}")
    found_keywords = [k for k in URGENCY_KEYWORDS if k in (subject + " " + body).lower()]
    if found_keywords:
        findings.append(f"Urgency / social engineering keywords: {', '.join(found_keywords)}")
        score += len(found_keywords) * 10
        print(f"  [!] Urgency keywords found: {found_keywords}")
    else:
        print("  [OK] No urgency keywords")
    
    # 3. URL Analysis
    print(f"\n[3] URL ANALYSIS")
    urls = extract_urls(body)
    if not urls:
        print("  [OK] No URLs found")
    for url in urls:
        print(f"  -> {url}")
        issues = check_url(url)
        if issues:
            for issue in issues:
                print(f"     [!] {issue}")
                findings.append(f"URL {url}: {issue}")
                score += 20
        else:
            print(f"     [OK] No obvious issues")
    
    # 4. Attachment Check (simulated from body mention)
    print(f"\n[4] ATTACHMENT CHECK")
    if any(ext in body.lower() for ext in [".exe", ".scr", ".zip", ".iso", ".html"]):
        findings.append("Suspicious attachment type mentioned (.exe/.zip/.iso)")
        score += 25
        print("  [!] Suspicious attachment type detected")
    else:
        print("  [OK] No suspicious attachment mentioned")
    
    # 5. Final Verdict
    print(f"\n{'='*60}")
    print(f"RISK SCORE: {score}/100")
    if score >= 70:
        verdict = "HIGH RISK - LIKELY PHISHING - BLOCK & ESCALATE"
    elif score >= 40:
        verdict = "MEDIUM RISK - SUSPICIOUS - QUARANTINE & INVESTIGATE"
    else:
        verdict = "LOW RISK - LIKELY LEGITIMATE"
    
    print(f"VERDICT: {verdict}")
    print(f"FINDINGS: {len(findings)}")
    for f in findings:
        print(f"  - {f}")
    
    # GRC Recommendation
    print(f"\n[RECOMMENDED ACTION]")
    if score >= 70:
        print("  1. Block sender domain")
        print("  2. Quarantine email, revoke if clicked")
        print("  3. Force password reset if user clicked link")
        print("  4. Escalate to SOC L2 with this report")
        print("  5. Add IOCs (URLs, sender) to blocklist")
    elif score >= 40:
        print("  1. Quarantine and monitor")
        print("  2. Ask user not to click, verify via official channel")
    else:
        print("  1. No action needed, release from quarantine")
    
    print(f"{'='*60}\n")
    return score, verdict, findings

# --- DEMO ---
if __name__ == "__main__":
    # Example 1: Phishing Email
    print("\n\n### TEST 1: SUSPICIOUS CEO EMAIL ###")
    analyze_email(
        sender="CEO John Smith <ceo@micros0ft-support.tk>",
        subject="URGENT: Verify Now - Account Suspended - Immediate Action Required",
        body="Dear employee, Your account will be suspended. Click here to verify now: http://192.168.1.50/login?user=admin or visit www.micros0ft-support.tk/verify. Also download invoice.zip to confirm. Action required immediately."
    )
    
    # Example 2: Legitimate Email
    print("\n\n### TEST 2: LEGITIMATE EMAIL ###")
    analyze_email(
        sender="HR Team <hr@rileyconsultech.com>",
        subject="Team Meeting Tomorrow",
        body="Hi team, Reminder about our meeting tomorrow at 10am. Agenda is attached in the shared drive: https://rileyconsultech.com/meeting-agenda"
    )