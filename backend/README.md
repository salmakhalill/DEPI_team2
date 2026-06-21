# NexusFlow Backend

The core scanning engine and API for **NexusFlow**.

This backend is built with **Django ASGI** and provides:
- Automated vulnerability scanning
- Dynamic crawling using **Playwright**
- Real-time scan telemetry via **WebSockets**
- Automated PDF security report generation

---

## Prerequisites

Before running the project, make sure you have:

- Python **3.10+**
- Git

---

# Local Setup & Installation

Follow these steps to configure and run the backend locally.

## 1. Clone the Repository

```bash
git clone <repository_url>
cd <repository_directory>
```

---

## 2. Create & Activate Virtual Environment

It is recommended to run the project inside an isolated virtual environment.

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

---

## 3. Install Dependencies

Install all required Python packages:

```bash
pip install -r requirements.txt
```

---

## 4. Install Playwright Browser

The scanner uses Playwright for headless browser interaction and dynamic attack surface mapping.

Install the required Chromium binaries:

```bash
playwright install chromium
```

---

## 5. Apply Database Migrations

Initialize the database schema:

```bash
python manage.py makemigrations
python manage.py migrate
```

---

## 6. Run Development Server

Start the ASGI server to support:

- HTTP requests
- WebSocket connections

```bash
python manage.py runserver
```

> **Note:**  
> Make sure the terminal shows:
>
> `Starting ASGI/Daphne version ...`
>
> If the server starts as WSGI, WebSocket functionality will not work.

---

# API & WebSocket Reference

The backend exposes the following endpoints for frontend integration.

---

## 1. Start a New Scan

Creates a new penetration testing scan instance.

### Endpoint

```
POST /api/scan/start/
```

### Payload

```json
{
  "target_url": "http://example.com",
  "raw_cookie_header": "session=token123"
}
```

### Response

Returns:

```
HTTP 201 Created
```

with the generated unique:

```
scan_id
```

---

## 2. Live Scan Telemetry

Streams real-time execution logs and vulnerability discoveries.

### Protocol

```
WebSocket (WS)
```

### Endpoint

```
ws://127.0.0.1:8000/ws/scan/<scan_id>/
```

### Behavior

- Broadcasts live JSON messages
- Sends updates after a short initialization delay

---

## 3. Scan Results Summary

Retrieves scan summary data for dashboard rendering.

### Endpoint

```
GET /api/scan/summary/<scan_id>/
```

### Response

Returns:

```
HTTP 200 OK
```

with:

- Threat matrices
- Scan status
- Aggregated results

---

## 4. Download PDF Security Report

Generates and returns the complete penetration testing report.

### Endpoint

```
GET /api/scan/report/<scan_id>/
```

### Response

Returns:

```
application/pdf
```

PDF report file stream.

---

# Project Architecture Overview

NexusFlow backend consists of:

- **Django ASGI API**
- **Playwright-based scanning engine**
- **WebSocket real-time communication layer**
- **Automated security report generator**
