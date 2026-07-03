# API Documentation

This document describes the backend API endpoints implemented in the current local version of NexusFlow.

## Related Documentation

- [README](../README.md)
- [Local Setup Guide](setup.md)
- [Architecture](architecture.md)
- [Testing Guide](testing.md)
- [Architecture Diagrams](diagrams/)

The backend runs locally at:

```text
http://localhost:8000
```

The WebSocket endpoint runs on the same host:

```text
ws://localhost:8000
```

There is currently no authentication layer for the scanner API. User accounts, dashboard authentication, scan ownership, scan history APIs, and role-based access control are not implemented in the current version.

## Endpoint Summary

| Purpose | Method | Route |
| --- | --- | --- |
| Start a scan | `POST` | `/api/scan/start/` |
| Download completed report | `GET` | `/api/scan/<scan_id>/report/` |
| Stream live scan telemetry | `WebSocket` | `/ws/scan/<scan_id>/` |

## Start Scan

### Purpose

Creates a new scan record, starts the scan pipeline in a background thread, and returns the generated scan ID.

The scan runs asynchronously after the HTTP response is returned. Live progress is available through the WebSocket endpoint.

### Method

```text
POST
```

### Route

```text
/api/scan/start/
```

### Parameters

No URL parameters.

### Body

Content type:

```text
application/json
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `target_url` | string | Yes | Target application URL to scan. |
| `raw_cookie_header` | string | No | Optional raw cookie header used for authenticated crawling and scanning. |

Example body:

```json
{
  "target_url": "http://127.0.0.1:5004",
  "raw_cookie_header": "session=example-session-cookie"
}
```

If `raw_cookie_header` is provided, the backend accepts values such as:

```text
session=abc123
```

or:

```text
Cookie: session=abc123; theme=dark
```

The current parser removes a leading `Cookie:` or `cookie:` prefix and ignores cookie attributes such as `Path`, `Domain`, `HttpOnly`, `Secure`, and `SameSite`.

### Response

Success status:

```text
201 Created
```

| Field | Type | Description |
| --- | --- | --- |
| `message` | string | Confirms that the scan was started. |
| `scan_id` | string | UUID of the created scan. |
| `status` | string | Initial scan status. Currently `Running`. |

### Example Request

```powershell
curl.exe -X POST http://localhost:8000/api/scan/start/ `
  -H "Content-Type: application/json" `
  -d "{\"target_url\":\"http://127.0.0.1:5004\",\"raw_cookie_header\":\"\"}"
```

### Example Response

```json
{
  "message": "Scan started.",
  "scan_id": "9f41c430-0e40-46a3-a7a4-7e0e3e2fd0de",
  "status": "Running"
}
```

### Error Responses

#### Missing Target URL

Status:

```text
400 Bad Request
```

Response:

```json
{
  "error": "target_url is required"
}
```

#### Invalid JSON Body

Handled by Django REST Framework before the view logic.

Typical status:

```text
400 Bad Request
```

Example response shape may vary depending on the parser error:

```json
{
  "detail": "JSON parse error"
}
```

## Download Report

### Purpose

Generates and downloads the PDF report for a completed scan.

The report can only be downloaded after the scan status is `Completed` and the scan has a stored `full_report_json`.

### Method

```text
GET
```

### Route

```text
/api/scan/<scan_id>/report/
```

### Parameters

| Parameter | Location | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `scan_id` | Path | UUID string | Yes | ID of the scan whose report should be downloaded. |

### Body

No request body.

### Response

Success status:

```text
200 OK
```

Content type:

```text
application/pdf
```

The response is a file download.

Response header:

```text
Content-Disposition: attachment; filename="Penetration_Test_Report_<scan_id>.pdf"
```

### Example Request

```bash
curl -L -o report.pdf http://localhost:8000/api/scan/9f41c430-0e40-46a3-a7a4-7e0e3e2fd0de/report/
```

### Example Response

The response body is binary PDF content.

Example headers:

```text
HTTP/1.1 200 OK
Content-Type: application/pdf
Content-Disposition: attachment; filename="Penetration_Test_Report_9f41c430-0e40-46a3-a7a4-7e0e3e2fd0de.pdf"
```

### Error Responses

#### Scan Not Found

Status:

```text
404 Not Found
```

Response:

```json
{
  "error": "Scan not found"
}
```

#### Report Not Ready

Returned when the scan is not completed or the final JSON report is not stored yet.

Status:

```text
400 Bad Request
```

Response:

```json
{
  "error": "Report not ready"
}
```

#### Generated PDF File Missing

Returned if report generation finishes but the expected PDF file cannot be found on disk.

Status:

```text
500 Internal Server Error
```

Response:

```json
{
  "error": "Failed to locate generated PDF file"
}
```

#### Invalid UUID Format

The route expects a UUID path converter. If the path segment does not match a UUID, Django will not route the request to the view.

Typical status:

```text
404 Not Found
```

## Live Scan Telemetry

### Purpose

Streams real-time scan messages from the backend orchestrator to the frontend.

The WebSocket receives scan lifecycle messages such as scanner initialization, crawler progress, discovered findings, correlation progress, report generation, and completion.

### Method

```text
WebSocket
```

### Route

```text
/ws/scan/<scan_id>/
```

Full local URL:

```text
ws://localhost:8000/ws/scan/<scan_id>/
```

### Parameters

| Parameter | Location | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `scan_id` | Path | string | Yes | Scan ID used to join the scan-specific Channels group. |

The WebSocket route accepts word characters and hyphens:

```text
[\w-]+
```

In normal use, this value is the UUID returned by `POST /api/scan/start/`.

### Body

No request body.

The client does not need to send messages after connecting. The current consumer only pushes backend telemetry to the client.

### Response

Each message is a JSON object with a `message` field.

| Field | Type | Description |
| --- | --- | --- |
| `message` | string | Live scan telemetry message emitted by the orchestrator. |

### Example Request

Browser JavaScript:

```javascript
const scanId = "9f41c430-0e40-46a3-a7a4-7e0e3e2fd0de";
const ws = new WebSocket(`ws://localhost:8000/ws/scan/${scanId}/`);

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(data.message);
};
```

### Example Responses

```json
{
  "message": "[*] Module Initialized: SQLInjectionScanner"
}
```

```json
{
  "message": "[*] Phase 1: Discovery & Attack Surface Mapping"
}
```

```json
{
  "message": "[Spider] Crawling: http://127.0.0.1:5004/dashboard"
}
```

```json
{
  "message": "[+] Attack Surface Extracted: 18 unique endpoints discovered."
}
```

```json
{
  "message": "[+] Scan 9f41c430-0e40-46a3-a7a4-7e0e3e2fd0de Completed Successfully!"
}
```

### Error Responses

WebSocket errors are connection-level events rather than JSON API responses.

Common cases:

| Case | Behavior |
| --- | --- |
| Backend is not running | WebSocket connection fails. |
| Invalid route | WebSocket connection is rejected or returns 404 during handshake. |
| Scan ID has no active listeners or no running scan | Connection may open, but no telemetry is sent. |
| Backend process exits | WebSocket connection closes. |

The current WebSocket implementation does not validate that the scan ID exists in the database before joining the group.

## Scan Status Values

The `Scan` model currently supports these statuses:

| Status | Meaning |
| --- | --- |
| `Running` | Scan row has been created and the background scan is executing or about to execute. |
| `Completed` | Scan pipeline finished and stored the final JSON report. |
| `Failed` | An unhandled exception occurred during background scan execution. |

There is currently no HTTP endpoint for polling scan status directly.

## Report Data

The report JSON is stored internally in the `Scan.full_report_json` field after scan completion. The current public API does not expose this JSON directly.

The only implemented report retrieval endpoint returns a generated PDF:

```text
GET /api/scan/<scan_id>/report/
```

## Not Implemented in the Current API

The following endpoints or features are not implemented in the current local backend:

- Scan list endpoint.
- Scan detail endpoint.
- Scan status polling endpoint.
- Raw JSON report endpoint.
- Finding list endpoint.
- User authentication endpoint.
- User management endpoint.
- Scan ownership or permissions.
- Scan cancellation endpoint.
- Scanner profile selection endpoint.

These may be future roadmap items, but they should not be treated as current API functionality.
