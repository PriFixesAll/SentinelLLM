# 🛡️ Kavach-Proxy: Enterprise LLM Security Gateway

**Kavach-Proxy** is a production-grade, FastAPI-based middleware security layer designed to sit between your application and Large Language Models (LLMs). It protects AI applications from **Prompt Injections, Jailbreaks, and Structural Tampering (HTML/XSS injections)** in real-time across user prompts, RAG documents, and tool outputs.

---

## 📂 Project Architecture & Folder Structure

```text
Kavach-Proxy/
│
├── app/                    # Core Backend Application
│   ├── __init__.py
│   ├── main.py             # FastAPI entrypoint & /v1/sanitize endpoint
│   ├── schemas/
│   │   └── payload.py      # Pydantic data validation models
│   └── services/
│       ├── sanitizer.py    # Structural sanitization layer (HTML/XSS stripping)
│       └── classifier.py   # Semantic classification & threat risk scoring
│
├── venv/                   # Python Virtual Environment
├── .gitignore              # Git ignore rules for clean repository
├── requirements.txt        # Project dependencies (FastAPI, Pydantic, Uvicorn, Requests)
├── dashboard.py            # Streamlit Interactive Security UI
├── demo_test.py            # Automated test suite for command-line demo
└── README.md               # Developer Handover & Documentation

✨ Core Features (The "AI Sandwich" Architecture)
Kavach-Proxy operates on a Zero-Trust Dual-Proxy Model (Ingress & Egress) ensuring end-to-end security without compromising on application latency.

🛡️ Ingress Filtering (Entry Gate):

Deterministic PII Masking: Automatically detects and masks sensitive data (10-digit Phone Numbers, 12-digit Aadhaar Cards) using pre-compiled, C-level Regex engine (re.compile) in <1ms.

Threat Neutralization: Blocks Prompt Injections, "DAN" (Do Anything Now) Jailbreaks, and malicious structural payloads (XSS/HTML) before they reach the LLM.

Cost Optimization: Drops malicious requests at the gateway, saving LLM API token costs ($0 spent on bad actors).

🧠 Seamless LLM Handoff: Acts as a transparent reverse proxy (httpx async client) forwarding sanitized prompts to upstream LLMs (OpenAI, Anthropic, LLaMA) with zero developer friction.

🚪 Egress Filtering (Exit Gate - Data Leak Prevention):

Scans the LLM's generated output before returning it to the user.

Prevents Canary Token leaks, internal System Prompt exfiltration, and accidental PII exposure.

User / Client App 
       │ 
       ▼ 
[ 🛡️ KAVACH INGRESS GATEWAY ] ──> 1. Structural Sanitize (XSS/HTML stripped)
       │                      ──> 2. PII Masking (Aadhaar/Phone -> [MASKED])
       │                      ──> 3. Threat Classification (If risk > threshold ➔ DROP 403)
       ▼ (Forward Masked Prompt)
[ 🧠 UPSTREAM LLM API ]       ──> (e.g., OpenAI gpt-3.5-turbo / Claude 3)
       │ 
       ▼ (LLM Output Generated)
[ 🚪 KAVACH EGRESS GATEWAY ]  ──> 4. Data Leak Prevention (Checks for Canary secrets)
       │                      ──> 5. Reverse Masking (Optional)
       ▼ (Safe Response)
User / Client App
