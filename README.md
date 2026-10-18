# AI-Powered Email Threat Detector & Forensic Intelligence Platform

An enterprise-grade email forensic analysis and threat intelligence platform. It analyzes suspicious emails (`.eml`, `.txt`, or raw RFC822 strings), calculates multi-vector phishing scores, maps delivery hops across the globe, generates cryptographic PDF forensic reports, and exposes a real-time reactive dashboard.

---

## Architecture Overview

```
                                      +-------------------------------+
                                      |   React 18 + Vite Frontend    |
                                      |   (TypeScript / Leaflet / CSS)|
                                      +---------------+---------------+
                                                      |
                                                      | Reverse Proxy / REST API
                                                      v
                                      +---------------+---------------+
                                      |   FastAPI 0.115 Application   |
                                      | (SlowAPI Rate Limiter / JWT)  |
                                      +-------+---------------+-------+
                                              |               |
               +------------------------------+               +-----------------------------+
               |                                                                            |
               v                                                                            v
+--------------+-------------------+                                          +-------------+--------------------+
|   Threat Intelligence Pipeline   |                                          |   PostgreSQL / Neon DB Engine    |
| - Header SPF/DKIM/DMARC Analysis |                                          | - SQLAlchemy 2.0 ORM             |
| - Scikit-Learn TF-IDF Phishing ML|                                          | - Alembic Schema Migrations      |
| - URL & Lookalike Domain Hunter  |                                          | - Preserved 990+ Legacy Scans    |
| - Attachment Risk Profiler       |                                          +----------------------------------+
| - IP Hop Trace & Geolocation     |
| - ReportLab PDF Forensic Engine  |
+----------------------------------+
```

---

## Key Features

- **Multi-Vector Phishing Detection**:
  - **Machine Learning**: Pre-warmed Scikit-learn TF-IDF vectorizer + Logistic Regression classifier.
  - **Header Forensics**: SPF, DKIM, and DMARC verification, `From` vs `Reply-To`/`Return-Path` anomaly detection, display-name spoofing, and lookalike domain detection.
  - **URL Threat Intelligence**: IP-based hosts, redirect shorteners, `@` symbol credential harvesting tricks, anchor text mismatches, punycode, and risky TLD inspection.
  - **Attachment Profiling**: Dangerous extensions, macro-enabled documents, double extensions, and hash verification (attachments are parsed safely without execution).
  - **Global Hop Geolocation**: Decodes the transmission path from raw `Received` headers, resolves relay IPs with geographic coordinates, and plots them on interactive CartoDB Leaflet maps.
- **Enterprise Security & Authentication**:
  - **Argon2id** password hashing with dual-verification fallback for legacy Werkzeug SHA256 hashes.
  - JWT Bearer authentication (`access` and `refresh` tokens).
  - Role-Based Access Control (`admin` vs `user`).
  - Rate limiting with **SlowAPI** to mitigate brute-force attacks.
- **Forensic PDF Export**:
  - Multi-page PDF reports generated with **ReportLab**, featuring executive threat gauges, granular score breakdowns, categorized findings, transmission route tables, and an immutable **SHA-256 digital chain of custody**.
- **Modern Cyber-Defense Web App**:
  - React 18 + TypeScript + Vite with a dark cyber-intelligence glassmorphic theme.
  - Live radial score gauges, interactive route maps, file drag-and-drop, filterable history, and admin user controls.

---

## Quick Start

### 1. Prerequisites
- Python 3.10+
- Node.js 18+ (for frontend)
- Docker & Docker Compose (optional, for containerized run)

### 2. Environment Configuration
Create a `.env` file in the root directory (or use `.env.example` as a template):

```bash
# Database (SQLite fallback or Neon PostgreSQL)
DATABASE_URL="postgresql://user:password@ep-sample-pooler.c-2.neon.tech/neondb?sslmode=require"

# Security & Secrets
JWT_SECRET_KEY="generate-a-strong-secret-key-here"
SECRET_KEY="generate-a-strong-secret-key-here"
JWT_ALGORITHM="HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Initial Superadmin Account
FIRST_SUPERUSER_EMAIL="admin@emailthreat.local"
FIRST_SUPERUSER_PASSWORD="ChangeThisPassword123!"

# Optional Integrations
VT_API_KEY=""
```

---

## Running with Docker Compose (Recommended)

To spin up both the FastAPI backend and the React Nginx frontend together:

```bash
docker compose up --build
```

- **Frontend Application**: [http://localhost](http://localhost) (or [http://localhost:5173](http://localhost:5173))
- **Backend API**: [http://localhost:8000](http://localhost:8000)
- **Interactive Swagger Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## Running Locally

### 1. Backend (FastAPI)

Activate your Python virtual environment and install dependencies:

```powershell
# Windows PowerShell
python -m venv venv
venv\Scripts\activate
pip install -r backend/requirements.txt
```

Run database migrations:
```powershell
alembic upgrade head
```

Launch the FastAPI development server:
```powershell
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

The API will be available at `http://127.0.0.1:8000`. Test the health endpoint:
```powershell
curl http://127.0.0.1:8000/health
```

### 2. Frontend (React + Vite + TypeScript)

In a separate terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser. API requests are automatically proxied to `http://127.0.0.1:8000`.

To create a production build:
```powershell
npm run build
```

---

## Automated Test Suite

The project includes an end-to-end integration and unit test suite powered by `pytest` and `httpx`:

```powershell
pytest tests/ -v
```

The test suite covers:
- `/api/auth/`: Health checks, registration, duplicate checks, login, profile retrieval, token refresh.
- `/api/scans/`: File upload scanning, raw RFC822 string scanning, findings breakdown, and PDF forensic generation.
- `/api/dashboard/`: Metrics calculation, risk distribution, 7-day trend series, model telemetry.
- ML Inference: TF-IDF vectorization and classification accuracy against legitimate and phishing emails.

---

## Legacy Flask App

The original Flask application remains fully operational for backward compatibility:

```powershell
python app.py
```
Open [http://127.0.0.1:5000](http://127.0.0.1:5000).

---

## Project Directory Structure

```
email-threat-detector/
├── backend/
│   ├── app/
│   │   ├── api/             # FastAPI routers (auth, scans, dashboard, admin, etc.)
│   │   ├── core/            # Config, database sessions, SlowAPI rate limiter
│   │   ├── ml/              # Scikit-learn inference pipeline
│   │   ├── models/          # SQLAlchemy 2.0 ORM models (User, EmailScan, etc.)
│   │   ├── reports/         # ReportLab PDF forensic intelligence generator
│   │   ├── schemas/         # Pydantic v2 schemas
│   │   ├── security/        # Argon2id, Werkzeug dual hashing, JWT token manager
│   │   ├── services/        # Scan & ingestion service orchestration
│   │   └── main.py          # FastAPI application entrypoint
│   └── requirements.txt     # Pinned backend dependencies
├── frontend/
│   ├── src/
│   │   ├── components/      # HopMap (Leaflet), ScoreGauge, Navbar, AuthModal
│   │   ├── views/           # DashboardView, ScannerView, ScanDetailView, HistoryView, AdminView
│   │   ├── api.ts           # Typed API client with JWT bearer handling
│   │   ├── App.tsx          # Main view router and auth state
│   │   └── index.css        # Cyber-intelligence design system
│   ├── nginx.conf           # SPA production Nginx config with reverse proxy
│   ├── Dockerfile           # Multi-stage frontend container build
│   └── package.json
├── alembic/                 # Alembic database migration scripts
├── tests/                   # Pytest automated test suite
├── Dockerfile.backend       # FastAPI production container build
├── docker-compose.yml       # Multi-service composition
└── README.md
```

---

## License

This project is licensed under the MIT License.
