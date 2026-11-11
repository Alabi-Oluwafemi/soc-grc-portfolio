import re

COMMON_PASSWORDS = ["password", "123456", "12345678", "qwerty", "admin", "letmein", "welcome", "12345", "password1", "123456789"]

def check_password(password):
    score = 0
    findings = []
    recommendations = []

    # Length check
    if len(password) >= 12:
        score += 25
    elif len(password) >= 8:
        score += 15
        findings.append("Password is okay length, but 12+ is stronger")
    else:
        findings.append(f"Too short: {len(password)} characters (minimum 8, recommended 12+)")
        recommendations.append("Use at least 12 characters")

    # Uppercase
    if re.search(r"[A-Z]", password):
        score += 15
    else:
        findings.append("No uppercase letters")
        recommendations.append("Add uppercase letters (A-Z)")

    # Lowercase
    if re.search(r"[a-z]", password):
        score += 15
    else:
        findings.append("No lowercase letters")
        recommendations.append("Add lowercase letters (a-z)")

    # Digits
    if re.search(r"[0-9]", password):
        score += 15
    else:
        findings.append("No numbers")
        recommendations.append("Add numbers (0-9)")

    # Symbols
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 15
    else:
        findings.append("No special characters")
        recommendations.append("Add symbols (!@#$%^&*)")

    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        findings.append("CRITICAL: This is a known common / breached password!")
        recommendations.append("Never use this password - change immediately")

    # Repeated characters
    if re.search(r"(.)\1\1", password):
        score -= 10
        findings.append("Contains repeated characters (e.g. aaa, 111)")

    score = max(0, min(100, score))

    if score >= 80:
        verdict = "STRONG - Safe to use"
    elif score >= 60:
        verdict = "MEDIUM - Usable but improve"
    elif score >= 40:
        verdict = "WEAK - Should be changed"
    else:
        verdict = "CRITICAL - Change immediately"

    print("\n" + "="*50)
    print("PASSWORD STRENGTH REPORT")
    print("="*50)
    print(f"Password Length: {len(password)} characters")
    print(f"Score: {score}/100")
    print(f"Verdict: {verdict}")
    print("\nFINDINGS:")
    if not findings:
        print("- No issues found - excellent password!")
    else:
        for f in findings:
            print(f"- {f}")
    print("\nRECOMMENDATIONS:")
    if not recommendations:
        print("- None - keep using a password manager")
    else:
        for r in recommendations:
            print(f"- {r}")
    print("="*50)
    return score

if __name__ == "__main__":
    print("### TEST 1: WEAK PASSWORD ###")
    check_password("password123")
    print("\n### TEST 2: STRONG PASSWORD ###")
    check_password("MySecure@2026!Pass")
    print("\n### TEST 3: YOUR TURN ###")
    user_pw = input("Enter a password to test (it will show on screen): ")
    check_password(user_pw)