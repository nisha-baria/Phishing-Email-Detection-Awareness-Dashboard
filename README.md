# 🛡️ Phishing Email Detection & Security Awareness Dashboard
A defensive cybersecurity application engineered to parse email telemetry, inspect suspicious sender behaviors, perform safe static URL/attachment analysis, and generate explainable threat assessments paired with an interactive user awareness training module.

## 📌 Project Overview
Email continues to represent the primary initial access vector across cyber attacks. Traditional filters often miss subtle social-engineering techniques or present black-box decisions without context. This platform combines:
1. **Multi-Vector Rule-Based Heuristics**: Immediate parsing of lexical indicators, lookalike domain traits, urgency, and disguised extensions.
2. **Defensive Explainability**: Maps flagged signals directly to actionable recommendations for SOC analysts and end users.
3. **Interactive Security Awareness**: Real-time educational checklists to foster human-layer defense.
4. **RESTful Architecture**: FastAPI service with SQLite persistence coupled with a Streamlit analytics dashboard.

## 🏗️ System Architecture
```text
Email Raw Input (Sender, Subject, Body, URL, Attachment)
                      │
                      ▼
               Pre-Processing
                      │
   ┌──────────────────┼──────────────────┬─────────────────┐
   ▼                  ▼                  ▼                 ▼
Sender Analyzer  Content Analyzer   URL Analyzer    Attachment Analyzer
(Lookalike TLDs, (Urgency, Fear,    (Static Lexical, (Disguised Double
 Subdomains)      Credentials)       Raw IP, Scheme)  Extensions)
   └──────────────────┬──────────────────┴─────────────────┘
                      │
                      ▼
             Risk Scoring Engine (0 - 100)
                      │
       ┌──────────────┴──────────────┐
       ▼                             ▼
FastAPI Backend (REST API)     Streamlit Dashboard
       │                             │
       ▼                             ▼
 SQLite Telemetry Store       Explainable SOC / Awareness View

## 🔍 Phishing Detection Indicators

The detection engine inspects incoming email vectors across four distinct layers without executing payloads:

* Sender Profile: Flags non-routable domains (RFC 2606), excessive subdomains, and administrative masquerading.

* Content & Semantics: Detects psychological manipulation keywords categorized into Urgency, Fear, Financial Pressure, and Credential Requests.

* Static URL Heuristics: Analyzes protocol security (HTTP vs. HTTPS), raw IP usage (e.g., 198.51.100.10), excessive paths, and credential-targeted keywords without detonating the link.

* Attachment Anatomy: Identifies dangerous executable binaries (.exe, .scr, .bat) and double-extension obfuscation techniques (e.g., .pdf.exe).

🚀 Quick Start Guide

1. Setup & Dependencies
# Go to project folder and activate venv
cd Phishing-Email-Detection-Awareness-Dashboard
venv\Scripts\activate

# Install Packages
pip install -r requirements.txt

2. Dataset & ML Model
python data/generate_dataset.py
python ml/train_model.py

3. Run Application
Terminal 1 (Backend API):uvicorn backend.app:app --reload --port 8000
Terminal 2 (Frontend Dashboard):streamlit run dashboard/streamlit_app.py

4. Access URLsDashboard: http://localhost:8501   
   API Docs (Swagger UI): http://localhost:8000/docs

## 📊 REST API Endpoints

* POST /api/analyze - Parses email metadata, computes risk score, logs findings to database, and outputs mitigation actions.
* GET /api/analyses - Retrieves telemetry log history.
* GET /api/dashboard/stats - Fetches aggregated triage metrics (Total, High Risk, Suspicious, Safe).

## 🧪 Automated Testing
Run automated unit tests covering benign and weaponized simulation vectors: pytest tests/

## 🔒 Safe Cybersecurity Disclaimer
This project is strictly designed for educational and defensive cybersecurity research. All sample datasets, domains, and IP addresses rely on reserved, fictional examples (RFC 2606 / RFC 5737). The tool executes no dynamic malware, does not establish external attack connections, and does not conduct credential harvesting.