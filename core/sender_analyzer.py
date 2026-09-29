import re


def analyze_sender(sender: str):
    findings = []
    risk_score = 0

    if not sender or "@" not in sender:
        return {
            "risk_score": 50,
            "findings": ["Invalid or missing sender format"],
            "is_suspicious": True,
        }

    sender = sender.strip().lower()
    parts = sender.split("@")
    domain = parts[-1]

    if "invalid.test" in domain or "test" in domain:
        risk_score += 25
        findings.append(
            "Sender utilizes synthetic or non-routable top-level domain."
        )

    subdomains = domain.split(".")
    if len(subdomains) > 3:
        risk_score += 20
        findings.append(
            f"Unusual number of subdomains in sender address ({len(subdomains)} levels)."
        )

    suspicious_prefixes = ["security-alert", "admin-verify", "billing-support"]
    if any(prefix in parts[0] for prefix in suspicious_prefixes):
        risk_score += 15
        findings.append(
            f"High-urgency administrative masquerade detected in mailbox prefix."
        )

    risk_score = min(risk_score, 100)
    return {
        "risk_score": risk_score,
        "domain": domain,
        "findings": (
            findings
            if findings
            else ["Sender domain format appears structured."]
        ),
        "is_suspicious": risk_score >= 30,
    }