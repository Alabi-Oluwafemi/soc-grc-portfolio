from collections import Counter, defaultdict

# Sample SOC log file - like what a firewall / server would produce
SAMPLE_LOGS = """
2026-11-12 09:01:12 FAILED LOGIN user=admin ip=192.168.1.50
2026-11-12 09:01:15 FAILED LOGIN user=admin ip=192.168.1.50
2026-11-12 09:01:18 FAILED LOGIN user=admin ip=192.168.1.50
2026-11-12 09:01:21 FAILED LOGIN user=admin ip=192.168.1.50
2026-11-12 09:01:24 FAILED LOGIN user=admin ip=192.168.1.50
2026-11-12 09:01:27 FAILED LOGIN user=admin ip=192.168.1.50
2026-11-12 09:01:30 SUCCESS LOGIN user=admin ip=192.168.1.50
2026-11-12 09:05:10 FAILED LOGIN user=jane ip=10.0.0.5
2026-11-12 09:06:11 FAILED LOGIN user=jane ip=10.0.0.5
2026-11-12 09:10:45 SUCCESS LOGIN user=mike ip=172.16.0.20
2026-11-12 09:15:00 PORT SCAN ip=45.155.204.11 ports=22,80,443,3389,8080
2026-11-12 09:20:00 MALWARE DETECTED ip=192.168.1.100 file=invoice.exe
2026-11-12 09:25:00 SUCCESS LOGIN user=admin ip=203.0.113.99
2026-11-12 09:30:00 FAILED LOGIN user=root ip=203.0.113.99
2026-11-12 09:30:05 FAILED LOGIN user=root ip=203.0.113.99
2026-11-12 09:30:10 FAILED LOGIN user=root ip=203.0.113.99
2026-11-12 09:30:15 FAILED LOGIN user=root ip=203.0.113.99
"""

def analyze_logs(log_text):
    lines = [l.strip() for l in log_text.strip().split("\n") if l.strip()]
    
    failed_by_ip = Counter()
    success_by_ip = Counter()
    alerts = []

    for line in lines:
        # Extract IP
        ip = "unknown"
        if "ip=" in line:
            ip = line.split("ip=")[1].split()[0]

        if "FAILED LOGIN" in line:
            failed_by_ip[ip] += 1
        if "SUCCESS LOGIN" in line:
            success_by_ip[ip] += 1
        if "PORT SCAN" in line:
            alerts.append(f"HIGH: Port Scan detected from {ip} - Possible attacker scanning network")
        if "MALWARE" in line:
            alerts.append(f"CRITICAL: Malware detected from {ip} - Isolate host immediately")

    # Brute Force Detection: 5+ failed logins from same IP
    for ip, count in failed_by_ip.items():
        if count >= 5:
            alerts.append(f"CRITICAL: Brute Force Attack from {ip} - {count} failed logins! Block IP.")
        elif count >= 3:
            alerts.append(f"MEDIUM: Suspicious login attempts from {ip} - {count} failed logins")

    # Impossible / Suspicious Success after many failures
    for ip in failed_by_ip:
        if failed_by_ip[ip] >= 5 and success_by_ip[ip] > 0:
            alerts.append(f"CRITICAL: Possible ACCOUNT COMPROMISE! {ip} had {failed_by_ip[ip]} fails then SUCCESS login. Force password reset!")

    # --- PRINT REPORT ---
    print("\n" + "="*60)
    print("SOC LOG ANALYSIS REPORT")
    print("="*60)
    print(f"Total Log Lines Analyzed: {len(lines)}")
    print(f"Total Failed Logins: {sum(failed_by_ip.values())}")
    print(f"Total Successful Logins: {sum(success_by_ip.values())}")
    print("\n--- FAILED LOGINS BY IP ---")
    for ip, count in failed_by_ip.most_common():
        print(f"- {ip}: {count} failed attempts")
    
    print("\n--- SECURITY ALERTS ---")
    if not alerts:
        print("- No alerts - All clear")
    else:
        for a in alerts:
            print(f"- {a}")
    
    print("\n--- RECOMMENDED ACTIONS ---")
    if any("CRITICAL" in a for a in alerts):
        print("- Block malicious IPs in firewall")
        print("- Force password reset for compromised accounts")
        print("- Isolate infected host from network")
        print("- Escalate to Incident Response Team")
    else:
        print("- Continue monitoring")
    print("="*60)

if __name__ == "__main__":
    analyze_logs(SAMPLE_LOGS)
    print("\nTry this: Change the numbers in SAMPLE_LOGS and run again to see alerts change!")