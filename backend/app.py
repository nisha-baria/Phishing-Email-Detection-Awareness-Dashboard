from backend.database import get_history, init_db, save_record
from core.risk_engine import calculate_phishing_score
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="Phishing Email Detection API",
    description="Defensive Cybersecurity REST API",
    version="1.0.0",
)

init_db()


class EmailAnalysisRequest(BaseModel):
    sender: str
    subject: str
    body: str
    urls: str = ""
    attachment_name: str = ""


@app.post("/api/analyze")
def analyze_email_endpoint(payload: EmailAnalysisRequest):
    result = calculate_phishing_score(
        sender=payload.sender,
        subject=payload.subject,
        body=payload.body,
        url=payload.urls,
        attachment_name=payload.attachment_name,
    )
    save_record(
        sender=payload.sender,
        subject=payload.subject,
        risk_score=result["risk_score"],
        classification=result["classification"],
        findings=result["findings"],
    )
    return result


@app.get("/api/analyses")
def read_analyses():
    records = get_history()
    return [
        {
            "id": r[0],
            "timestamp": r[1],
            "sender": r[2],
            "subject": r[3],
            "risk_score": r[4],
            "classification": r[5],
            "findings": r[6].split("; "),
        }
        for r in records
    ]


@app.get("/api/dashboard/stats")
def dashboard_stats():
    records = get_history(200)
    total = len(records)
    high_risk = sum(1 for r in records if r[4] >= 71)
    suspicious = sum(1 for r in records if 45 < r[4] < 71)
    safe = sum(1 for r in records if r[4] <= 45)
    return {
        "total_analyzed": total,
        "high_risk": high_risk,
        "suspicious": suspicious,
        "safe_or_low": safe,
    }