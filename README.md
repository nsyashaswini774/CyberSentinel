# CyberSentinel AI

> **AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform**  
> Built for the Smart India Hackathon (SIH) Email Threat Analysis Problem Statement.

---

## Architecture Overview

- **Backend:** Python 3.14 + FastAPI (Async REST APIs, RFC 5322 Forensics, Threat Intelligence, PDF Report Generation)
- **Frontend:** React 18 + Vite + TypeScript + Tailwind CSS (SOC-style Dark UI)
- **Database:** SQLite with SQLAlchemy 2.0 ORM (`cybersentinel.db`)

---

## Project Structure

```
CyberSentinel-AI/
├── backend/
│   ├── app/
│   │   ├── api/v1/endpoints/        # health.py, analyze.py, reports.py
│   │   ├── core/                    # config.py, database.py
│   │   ├── models/                  # scan.py (SQLAlchemy models)
│   │   ├── schemas/                 # email.py (Pydantic validation schemas)
│   │   ├── services/                # Forensic engines & scoring modules
│   │   └── main.py                  # FastAPI application entry point
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── components/              # Modular UI elements
│   │   ├── services/                # api.ts (Axios client)
│   │   ├── types/                   # TypeScript interfaces
│   │   ├── App.tsx                  # Main SOC dashboard
│   │   └── index.css                # Tailwind CSS styling
│   ├── package.json
│   └── vite.config.ts
├── start_backend.bat                # 1-click startup for FastAPI
├── start_frontend.bat               # 1-click startup for React UI
└── README.md
```

---

## Getting Started

### 1. Backend
To run manually:
```bash
cd backend
venv\Scripts\activate
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
- Interactive API Docs: `http://localhost:8000/api/v1/docs`
- Health Endpoint: `http://localhost:8000/api/v1/health`

### 2. Frontend
To run manually:
```bash
cd frontend
npm run dev
```
- Open browser: `http://localhost:5173`

---

## Roadmap

- [x] **Phase 1: Environment & Project Foundation** (Completed)
- [ ] **Phase 2: Email Ingestion & RFC Parsing Engine** (Next)
- [ ] **Phase 3: Threat Intelligence & IP Geolocation**
- [ ] **Phase 4: AI & Heuristic Threat Scoring Engine**
- [ ] **Phase 5: Cybersecurity Dashboard Visualizations**
- [ ] **Phase 6: Forensic Report Export & History Logging**
