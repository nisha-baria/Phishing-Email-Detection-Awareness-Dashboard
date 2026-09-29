import os
import sys

# Project root folder ne Python path ma add karo
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

import pandas as pd
import requests
import streamlit as st
from core.risk_engine import calculate_phishing_score

st.set_page_config(page_title="Phishing Defense Dashboard", layout="wide")
st.title("🛡️ Phishing Email Detection & Security Awareness Dashboard")

tab1, tab2, tab3 = st.tabs(
    ["Email Inspector", "Security Awareness", "Analysis Telemetry"]
)

with tab1:
    st.subheader("Analyze Suspect Email Metadata")
    col1, col2 = st.columns(2)
    with col1:
        sender_in = st.text_input(
            "Sender Email", "security-alert@account-check.invalid.test"
        )
        subject_in = st.text_input(
            "Email Subject", "URGENT: Verify Your Account Immediately"
        )
        url_in = st.text_input(
            "Embedded URL (Optional)", "http://198.51.100.10/verify-account"
        )
        attachment_in = st.text_input(
            "Attachment Filename (Optional)", "verification_form.pdf.exe"
        )
    with col2:
        body_in = st.text_area(
            "Email Body",
            "Your account access will be terminated within 24 hours. Verify your password immediately.",
            height=180,
        )

    if st.button("Run Threat Analysis"):
        payload = {
            "sender": sender_in,
            "subject": subject_in,
            "body": body_in,
            "urls": url_in,
            "attachment_name": attachment_in,
        }

        try:
            # FastAPI endpoint ne POST request moklo
            response = requests.post(
                "http://127.0.0.1:8000/api/analyze", json=payload, timeout=5
            )
            if response.status_code == 200:
                res = response.json()
            else:
                st.error("API error: " + response.text)
                res = calculate_phishing_score(**payload)
        except Exception:
            # Backend bandh hoy to fallback run thashe
            res = calculate_phishing_score(**payload)

        score = res["risk_score"]
        colA, colB = st.columns(2)
        colA.metric(label="Calculated Phishing Risk", value=f"{score}/100")
        colB.metric(label="Classification", value=res["classification"])

        st.markdown("### Detected Indicators")
        for find in res["findings"]:
            st.error(f"🚩 {find}")

        st.markdown("### Recommended SOC / User Actions")
        for rec in res["recommendations"]:
            st.info(f"✅ {rec}")

with tab2:
    st.subheader("Interactive Phishing Awareness Checklist")
    st.markdown("""
    - **Verify Sender Domains**: Double check domain extensions and typo lookalikes.
    - **Static URL Inspection**: Never click unknown links directly; inspect the domain string first.
    - **Urgency is a Red Flag**: Attacks rely on psychological pressure (e.g., 'Within 24 hours').
    - **Never Trust Double Extensions**: Attackers use names like `.pdf.exe` to hide malware.
    """)

with tab3:
    st.subheader("Historical Telemetry")
    try:
        r = requests.get("http://localhost:8000/api/analyses", timeout=3)
        if r.status_code == 200:
            df = pd.DataFrame(r.json())
            st.dataframe(df, use_container_width=True)
    except Exception:
        st.warning(
            "Start FastAPI backend (`uvicorn backend.app:app --port 8000`) to visualize SQLite telemetry."
        )