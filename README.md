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
