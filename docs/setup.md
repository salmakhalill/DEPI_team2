# Local Setup Guide

This guide explains how to run the NexusFlow DAST scanner locally for development and demonstration.

## Related Documentation

- [README](../README.md)
- [Architecture](architecture.md)
- [API Documentation](api.md)
- [Testing Guide](testing.md)
- [Architecture Diagrams](diagrams/)

The project has three runnable parts:

- Django backend: scanner API, WebSocket telemetry, scan orchestration, and report generation.
- React frontend: user interface for starting scans and viewing live progress.
- Flask vulnerable application: intentionally vulnerable local target used for scanner testing.

Run each part in a separate terminal.

## Prerequisites

Install the following before starting:

- Python 3.10 or newer
- Node.js and npm
- Git
- A terminal that can run PowerShell commands on Windows
- Chromium browser binaries installed through Playwright

The project is currently configured for local ports:

| Service | URL |
| --- | --- |
| Frontend | `http://localhost:3000` |
| Backend | `http://localhost:8000` |
| Vulnerable app | `http://127.0.0.1:5004` |

## Virtual Environment

Use separate Python virtual environments for the backend and vulnerable application. This keeps Django scanner dependencies separate from the Flask target application dependencies.

Backend virtual environment:

```powershell
cd backend
python -m venv venv
venv\Scripts\activate
```

Vulnerable application virtual environment:

```powershell
cd vulnerable_app
python -m venv venv
venv\Scripts\activate
```

If a virtual environment is active, the terminal prompt usually shows `(venv)`.

## Requirements Installation

Install backend dependencies:

```powershell
cd backend
venv\Scripts\activate
pip install -r requirements.txt
```

Install Playwright Chromium for crawling and PDF generation:

```powershell
playwright install chromium
```

Install vulnerable application dependencies:

```powershell
cd vulnerable_app
venv\Scripts\activate
pip install -r requirements.txt
```

Install frontend dependencies:

```powershell
cd frontend\nexusflow
npm install
```

## `.env` Configuration

The backend loads environment variables from `backend/.env`.

Create this file if it does not exist:

```powershell
cd backend
New-Item -ItemType File -Path .env
```

Add a local Django secret key:

```env
SECRET_KEY=replace-with-a-local-development-secret
```

Only `SECRET_KEY` is required by the current backend implementation.

Redis, Celery, PostgreSQL, external workers, and production deployment variables are not required for the current local implementation.

## Django Setup

From the backend directory:

```powershell
cd backend
venv\Scripts\activate
python manage.py migrate
```

Start the backend:

```powershell
python manage.py runserver
```

The backend should run at:

```text
http://localhost:8000
```

Current backend endpoints:

```text
POST /api/scan/start/
GET  /api/scan/<scan_id>/report/
WS   /ws/scan/<scan_id>/
```

## React Setup

From the frontend directory:

```powershell
cd frontend\nexusflow
npm install
npm run dev
```

Open:

```text
http://localhost:3000
```

The frontend currently connects to:

```text
http://localhost:8000
ws://localhost:8000/ws/scan/<scan_id>/
```

These URLs are defined in:

```text
frontend/nexusflow/src/api/client.ts
```

## Vulnerable Application Setup

From the vulnerable application directory:

```powershell
cd vulnerable_app
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open:

```text
http://127.0.0.1:5004
```

The vulnerable app initializes its local SQLite database and seeds demo data when it starts. It is intentionally insecure and should only be used as a local test target.

## Execution Order

Use this order for the least friction:

1. Start the vulnerable application.
2. Start the Django backend.
3. Start the React frontend.
4. Open `http://localhost:3000`.
5. Start a scan against:

```text
http://127.0.0.1:5004
```

If testing authenticated crawling, log in to the vulnerable app in a browser, copy the `session` cookie, and paste it into the frontend as a raw cookie header:

```text
session=<cookie-value>
```

## Troubleshooting

### Backend fails because `SECRET_KEY` is missing

Check that `backend/.env` exists and contains:

```env
SECRET_KEY=replace-with-a-local-development-secret
```

Restart the backend after editing `.env`.

### Playwright browser errors

Install Chromium from the backend virtual environment:

```powershell
cd backend
venv\Scripts\activate
playwright install chromium
```

The crawler and PDF generator both depend on Playwright browser binaries.

### WebSocket does not connect

Confirm the backend is running on port `8000`.

Confirm the frontend is using:

```text
ws://localhost:8000/ws/scan/<scan_id>/
```

Also confirm that the scan ID in the WebSocket URL matches the scan ID returned by `POST /api/scan/start/`.

### Frontend cannot start a scan

Check that the backend is running:

```text
http://localhost:8000
```

Check that CORS allows the frontend origin. The current backend settings allow:

```text
http://localhost:3000
```

If the frontend is started on a different port, either use port `3000` or update backend CORS settings for local development.

### Report endpoint returns `Report not ready`

The PDF report is only available after the scan status becomes `Completed`.

Wait for the live scan to finish, then open:

```text
http://localhost:8000/api/scan/<scan_id>/report/
```

### Vulnerable app is not reachable

Confirm it is running on:

```text
http://127.0.0.1:5004
```

Start it with:

```powershell
cd vulnerable_app
venv\Scripts\activate
python app.py
```

### Scan finds fewer endpoints than expected

Common causes:

- The vulnerable app was not running before the scan started.
- The target URL was entered incorrectly.
- Authenticated pages require a valid session cookie.
- The crawler is limited to the same hostname as the target URL.
- Some pages require interactions that the current crawler does not perform.

## Common Mistakes

- Running only the frontend and forgetting to start the backend.
- Running only the backend and forgetting to start the vulnerable app.
- Starting the frontend on a port other than `3000` while backend CORS only allows `http://localhost:3000`.
- Forgetting to run `python manage.py migrate` before starting the backend.
- Forgetting `playwright install chromium`.
- Using `localhost:5004` in one place and `127.0.0.1:5004` in another while copying cookies between browser sessions.
- Pasting the entire browser cookie table instead of a raw cookie header such as `session=<value>`.
- Expecting Redis, Celery, PostgreSQL, production workers, authentication, or scan history APIs to exist in the current local version.
- Calling report endpoints that are not implemented. The active report endpoint is:

```text
GET /api/scan/<scan_id>/report/
```
