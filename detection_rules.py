# detection_rules.py
# SOC Detection Rules - SOC + GRC Portfolio

def check_impossible_travel(log):
    # Rule: CEO Impossible Travel
    # If CEO logs in from outside Nigeria, it's CRITICAL
    if log["user"] == "ceo_account" and log["country"] != "Nigeria" and log["status"] == "success":
        return "CRITICAL: CEO Impossible Travel - Possible Account Compromise!"
    return "OK"

def check_brute_force(failed_logins, ip):
    # Rule: Brute Force Detection
    # If more than 5 failed logins, block IP
    if failed_logins > 5:
        return f"HIGH: Brute Force Detected from {ip} - Block IP NOW"
    return "OK"

# Test our rules with real incidents from today
test_log = {"user": "ceo_account", "country": "Russia", "status": "success"}
print(check_impossible_travel(test_log))
print(check_brute_force(500, "45.155.204.11"))