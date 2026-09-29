from core.attachment_analyzer import analyze_attachment
from core.content_analyzer import analyze_content
from core.sender_analyzer import analyze_sender
from core.url_analyzer import analyze_url


def calculate_phishing_score(
    sender: str,
    subject: str,
    body: str,
    url: str = "",
    attachment_name: str = "",
):
    sender_res = analyze_sender(sender)
    url_res = analyze_url(url)
    attach_res = analyze_attachment(attachment_name)
    content_res = analyze_content(subject, body)

    # Weighted composition
    total_score = (
        (content_res["risk_score"] * 0.35)
        + (url_res["risk_score"] * 0.30)
        + (attach_res["risk_score"] * 0.20)
        + (sender_res["risk_score"] * 0.15)
    )
    total_score = round(min(total_score, 100), 2)

    # Classification buckets
    if total_score <= 20:
        classification = "SAFE / LOW RISK"
    elif total_score <= 45:
        classification = "MODERATE RISK"
    elif total_score <= 70:
        classification = "SUSPICIOUS"
    else:
        classification = "HIGH RISK / LIKELY PHISHING"

    all_findings = []
    all_findings.extend(sender_res["findings"])
    all_findings.extend(content_res["findings"])
    all_findings.extend(url_res["findings"])
    all_findings.extend(attach_res["findings"])

    recommendations = []
    if total_score > 40:
        recommendations.append(
            "Do not click on links or authenticate via embedded forms."
        )
        recommendations.append(
            "Do not download or execute file attachments from this email."
        )
        recommendations.append(
            "Verify the communication directly via a trusted out-of-band channel."
        )
        recommendations.append("Report the message to the internal SOC team.")
    else:
        recommendations.append(
            "Standard business communication detected. Practice standard hygiene."
        )

    return {
        "risk_score": total_score,
        "classification": classification,
        "findings": all_findings,
        "recommendations": recommendations,
        "details": {
            "sender": sender_res,
            "content": content_res,
            "url": url_res,
            "attachment": attach_res,
        },
    }