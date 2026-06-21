# NexusFlow Backend

The core scanning engine and API for NexusFlow. Built with Django ASGI, this backend handles automated vulnerability scanning (utilizing Playwright for dynamic crawling), broadcasts real-time telemetry via WebSockets, and generates comprehensive PDF security reports.

## Prerequisites

- Python 3.10+
- Git

## Local Setup & Installation

Follow these steps to configure and run the backend environment locally.

### 1. Clone the Repository
```bash
git clone <repository_url>
cd <repository_directory>
```
2. Configure the Virtual Environment
It is highly recommended to run this project within an isolated virtual environment.

For Windows:

```Bash
python -m venv venv
venv\Scripts\activate
```

3. Install Dependencies
Install the required Python packages from the requirements file:

```Bash
pip install -r requirements.txt
```
4. Initialize Playwright
The scanner utilizes Playwright for headless browser interaction and dynamic attack surface mapping. You must install the required Chromium binaries:

```Bash
playwright install chromium
```
5. Database Migrations
Apply the initial schema structures to your local SQLite database:

```Bash
python manage.py makemigrations
python manage.py migrate
```
6. Start the Development Server
Launch the ASGI development server to support both standard HTTP requests and asynchronous WebSocket connections:

```Bash
python manage.py runserver
```
Note: Ensure the terminal outputs Starting ASGI/Daphne version ... upon successful launch. If it defaults to WSGI, WebSocket functionality will not work.

API & WebSocket Reference
The following endpoints are exposed for frontend integration:

1. Start a New Scan
Initializes a new penetration testing instance.

Endpoint: POST /api/scan/start/

Payload: 
```json
{
"target_url": "http://example.com",
"raw_cookie_header": "session=token123"
}
```

Returns: HTTP 201 Created with the unique scan_id.

2. Live Scan Telemetry
Streams real-time execution logs and vulnerability discoveries.

Protocol: WebSocket (WS)

Endpoint: ws://127.0.0.1:8000/ws/scan/<scan_id>/

Behavior: Broadcasts JSON messages after a brief 10-second initialization delay.

3. Scan Results Summary
Retrieves a lightweight executive summary for dashboard rendering.

Endpoint: GET /api/scan/summary/<scan_id>/

Returns: HTTP 200 OK with aggregated threat matrices and status.

4. Download Full PDF Report
Generates and serves the compiled penetration testing report.

Endpoint: GET /api/scan/report/<scan_id>/

Returns: application/pdf file stream.