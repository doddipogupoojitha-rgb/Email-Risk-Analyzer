import re
from datetime import datetime

def parse_headers(email_text):
    headers = {}
    for line in email_text.split('\n'):
        if ':' in line and line[0] != ' ':
            key, val = line.split(':', 1)
            headers[key.strip().lower()] = val.strip()
    return headers

def analyze_email(email_content):
    report = []
    risk_score = 0
    headers = parse_headers(email_content)
    
    print("="*60)
    print("EMAIL RISK ANALYZER - Workora Task")
    print("="*60)
    
    spf = headers.get('received-spf', headers.get('spf', 'Not Found'))
    dkim = headers.get('dkim-signature', headers.get('authentication-results', 'Not Found'))
    return_path = headers.get('return-path', 'Not Found')
    
    print(f"\n[1] HEADER ANALYSIS:")
    if 'fail' in spf.lower() or 'not found' in spf.lower():
        print(f"  SPF: {spf} -> SUSPICIOUS (+30)")
        risk_score += 30
        report.append("SPF check failed or missing")
    else:
        print(f"  SPF: PASS")
    
    if 'not found' in dkim.lower():
        print(f"  DKIM: Missing -> SUSPICIOUS (+25)")
        risk_score += 25
        report.append("DKIM missing")
    else:
        print(f"  DKIM: Found")
    
    body = email_content.lower()
    suspicious_links = re.findall(r'http[s]?://[^\s]+', body)
    urgent_keywords = ['urgent', 'immediate action', 'verify now', 'account suspended', 'click here', 'limited time', 'act now']
    
    print(f"\n[2] BODY SCAN:")
    for link in suspicious_links:
        if 'bit.ly' in link or 'tinyurl' in link or len(link) > 75:
            print(f"  Suspicious link: {link} (+20)")
            risk_score += 20
            report.append(f"Suspicious link: {link}")
    
    found = [k for k in urgent_keywords if k in body]
    if found:
        print(f"  Urgent keywords: {found} (+25)")
        risk_score += len(found) * 10
        report.append(f"Urgent words: {found}")
    
    risk_score = min(risk_score, 100)
    if risk_score < 30:
        level = "LOW - Likely Safe"
    elif risk_score < 70:
        level = "MEDIUM - Suspicious"
    else:
        level = "HIGH - Likely Phishing"
    
    print(f"\n[3] RISK SCORE: {risk_score}/100 -> {level}")
    print(f"\n[4] AUDIT REPORT - Issues: {len(report)}")
    for i, r in enumerate(report, 1):
        print(f"  {i}. {r}")
    print(f"Final Verdict: {level}")
    return risk_score, report

sample_email = """
From: support@paypal-secure-login.com
Return-Path: noreply@gmail.com
Received: from unknown-server (192.168.1.1)
Received-SPF: fail
DKIM-Signature: Not Found
Subject: Urgent: Your Account Suspended - Verify Now!

Dear user, Your account suspended. Immediate action required!
Click here: http://bit.ly/paypal-verify-account-login-secure-update
Limited time - Act now or account will be deleted.
"""

if __name__ == "__main__":
    analyze_email(sample_email)
