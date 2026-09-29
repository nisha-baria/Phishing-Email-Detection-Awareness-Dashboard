import re
from urllib.parse import urlparse


def analyze_url(url: str):
    findings = []
    risk_score = 0
    if not url or not url.strip():
        return {
            "risk_score": 0,
            "findings": ["No URL present"],
            "is_suspicious": False,
        }

    url = url.strip()
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Rule 1: Non-HTTPS
    if scheme == "http":
        risk_score += 20
        findings.append("Insecure HTTP scheme detected.")

    # Rule 2: Raw IP Usage
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$"
    if re.match(ip_pattern, netloc):
        risk_score += 40
        findings.append(
            "Host is a raw IP address instead of a registered domain name."
        )

    # Rule 3: Excessive Subdomains
    subdomain_parts = netloc.split(".")
    if len(subdomain_parts) > 3 and not re.match(ip_pattern, netloc):
        risk_score += 20
        findings.append(
            f"Excessive subdomain layers detected ({len(subdomain_parts) - 2} levels)."
        )

    # Rule 4: Suspicious Keywords in Path/Hostname
    suspicious_keywords = [
        "login",
        "verify",
        "update",
        "account",
        "bank",
        "secure",
        "token",
        "claim",
    ]
    matched = [kw for kw in suspicious_keywords if kw in url.lower()]
    if matched:
        risk_score += 25
        findings.append(
            f"Credential/security keywords detected in URL: {', '.join(matched)}"
        )

    # Rule 5: Lookalike keyword markers
    lookalikes = ["paypa1", "micr0soft", "amaz0n", "sec-check"]
    if any(l in netloc for l in lookalikes):
        risk_score += 35
        findings.append("Typosquatting/lookalike domain pattern detected.")

    risk_score = min(risk_score, 100)
    return {
        "risk_score": risk_score,
        "findings": (
            findings if findings else ["No obvious malicious URL indicators."]
        ),
        "is_suspicious": risk_score >= 40,
    }