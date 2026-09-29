def analyze_content(subject: str, body: str):
    text = f"{subject or ''} {body or ''}".lower()
    findings = []
    risk_score = 0

    categories = {
        "URGENCY": [
            "immediately",
            "urgent",
            "act fast",
            "24 hours",
            "right now",
        ],
        "FEAR_PRESSURE": [
            "suspended",
            "terminated",
            "locked",
            "legal action",
            "prosecution",
        ],
        "CREDENTIAL_REQUEST": [
            "verify your password",
            "login credentials",
            "confirm identity",
            "reset pin",
        ],
        "FINANCIAL_PRESSURE": [
            "unpaid invoice",
            "wire transfer",
            "overdue",
            "penalty",
            "gift card",
        ],
        "GENERIC_GREETING": [
            "dear customer",
            "dear user",
            "undisclosed recipients",
        ],
    }

    for cat, kws in categories.items():
        matched = [k for k in kws if k in text]
        if matched:
            weight = (
                25
                if cat == "CREDENTIAL_REQUEST"
                else 20
                if cat in ["URGENCY", "FEAR_PRESSURE"]
                else 10
            )
            risk_score += weight
            findings.append(f"{cat} indicators detected: {', '.join(matched)}")

    return {
        "risk_score": min(risk_score, 100),
        "findings": findings if findings else ["No high-risk keywords noted."],
    }