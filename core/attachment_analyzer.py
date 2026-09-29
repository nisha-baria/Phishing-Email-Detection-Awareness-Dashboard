import os


def analyze_attachment(filename: str):
    if not filename or not filename.strip():
        return {
            "risk_score": 0,
            "findings": ["No attachment provided"],
            "is_suspicious": False,
        }

    filename = filename.strip().lower()
    findings = []
    risk_score = 0

    dangerous_extensions = {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".js",
        ".vbs",
        ".ps1",
        ".hta",
    }
    double_ext_pattern = [
        ".pdf.exe",
        ".doc.exe",
        ".jpg.exe",
        ".txt.vbs",
        ".docx.scr",
    ]

    for de in double_ext_pattern:
        if filename.endswith(de):
            risk_score += 60
            findings.append(
                f"Double extension masquerade detected ({de}). High risk file disguise."
            )

    _, ext = os.path.splitext(filename)
    if ext in dangerous_extensions:
        risk_score += 50
        findings.append(
            f"Potentially executable or script extension detected ({ext})."
        )

    risk_score = min(risk_score, 100)
    return {
        "risk_score": risk_score,
        "findings": (
            findings if findings else ["Safe static extension profile."]
        ),
        "is_suspicious": risk_score >= 40,
    }