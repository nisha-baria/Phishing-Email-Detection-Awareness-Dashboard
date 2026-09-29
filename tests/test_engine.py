from core.attachment_analyzer import analyze_attachment
from core.risk_engine import calculate_phishing_score
from core.url_analyzer import analyze_url


def test_benign_email():
    res = calculate_phishing_score(
        sender="notifications@portal.example.com",
        subject="Monthly Meeting Agenda",
        body="Attached is the agenda for tomorrow's team sync.",
    )
    assert res["risk_score"] <= 25
    assert "SAFE" in res["classification"]


def test_urgent_credential_phish():
    res = calculate_phishing_score(
        sender="security@invalid.test",
        subject="URGENT: Verify Password Immediately",
        body="Your account will be suspended. Verify your credentials.",
        url="http://198.51.100.10/login",
    )
    assert res["risk_score"] >= 70
    assert "HIGH RISK" in res["classification"]


def test_double_extension_attachment():
    res = analyze_attachment("invoice.pdf.exe")
    assert res["is_suspicious"] is True
    assert res["risk_score"] >= 60


def test_ip_url_detection():
    res = analyze_url("http://192.0.2.1/login")
    assert res["is_suspicious"] is True
    assert any("raw IP" in f for f in res["findings"])