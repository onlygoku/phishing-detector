import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure",
    "account", "bank", "signin", "confirm"
]

def is_ip_address(url):
    return re.match(r"https?://\d+\.\d+\.\d+\.\d+", url)

def count_dots(domain):
    return domain.count(".")

def analyze_url(url):
    score = 0
    reasons = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if not parsed.scheme.startswith("https"):
        score += 1
        reasons.append("Uses HTTP instead of HTTPS")

    if is_ip_address(url):
        score += 2
        reasons.append("Uses IP address instead of domain")

    if count_dots(domain) > 3:
        score += 1
        reasons.append("Too many dots in domain")

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            score += 1
            reasons.append(f"Suspicious keyword found: {keyword}")
            break

    return score, reasons

def verdict(score):
    if score <= 1:
        return "Likely Safe"
    elif score <= 3:
        return "Suspicious"
    else:
        return "Likely Phishing"

def main():
    url = input("Enter URL to analyze: ").strip()
    score, reasons = analyze_url(url)

    print("\nAnalysis Result")
    print("----------------")

    for reason in reasons:
        print(f"- {reason}")

    print(f"\nRisk Score: {score}")
    print(f"Verdict  : {verdict(score)}")

if __name__ == "__main__":
    main()
