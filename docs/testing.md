# Testing Guide

This document describes the testing and validation approach for the current local implementation of NexusFlow.

## Related Documentation

- [README](../README.md)
- [Local Setup Guide](setup.md)
- [Architecture](architecture.md)
- [API Documentation](api.md)
- [Architecture Diagrams](diagrams/)

## Testing Scope

The current testing scope focuses on validating the local DAST workflow end to end:

- Starting the vulnerable Flask application.
- Starting the Django backend.
- Starting the React frontend.
- Launching a scan against the local vulnerable target.
- Observing live WebSocket telemetry.
- Verifying that the scanner pipeline completes.
- Downloading the generated PDF report.
- Reviewing generated findings for expected vulnerability classes.

The project is not currently tested as a production deployment. Redis, Celery, PostgreSQL, user authentication, scan history, distributed workers, and production scalability are future roadmap items and are not part of the current validation scope.

## Validation Target

The primary validation target is the local vulnerable application:

```text
http://127.0.0.1:5004
```

The vulnerable application was built specifically for this project so scanner behavior can be validated against controlled, repeatable vulnerability scenarios. This supports deterministic testing, predictable milestones, easier debugging, and stable demonstration results.

## Manual End-to-End Test

Use the setup instructions in [setup.md](setup.md), then run the following validation sequence.

1. Start the vulnerable application.
2. Start the Django backend.
3. Start the React frontend.
4. Open the frontend at `http://localhost:3000`.
5. Start a scan against `http://127.0.0.1:5004`.
6. Confirm that live scan telemetry appears in the frontend.
7. Wait for the scan to complete.
8. Open or download the generated PDF report.
9. Confirm that the report contains a summary, severity distribution, detailed findings, proof-of-concept evidence, and recommendations.

## API-Level Validation

The active backend API is documented in [docs/api.md](api.md). At minimum, validation should cover:

| Area | Expected Result |
| --- | --- |
| `POST /api/scan/start/` with a valid target | Returns `201 Created`, a `scan_id`, and status `Running`. |
| `POST /api/scan/start/` without `target_url` | Returns `400 Bad Request`. |
| `ws://localhost:8000/ws/scan/<scan_id>/` | Opens a WebSocket connection and receives scan telemetry while the scan runs. |
| `GET /api/scan/<scan_id>/report/` before completion | Returns `400 Bad Request` with `Report not ready`. |
| `GET /api/scan/<scan_id>/report/` after completion | Returns an `application/pdf` file response. |
| `GET /api/scan/<unknown_scan_id>/report/` | Returns `404 Not Found`. |

There is currently no scan status polling endpoint, scan list endpoint, raw JSON report endpoint, scan cancellation endpoint, or user authentication endpoint.

## Scanner Validation Areas

The current scanner registry includes modules for:

- SQL Injection.
- Reflected Cross-Site Scripting.
- Stored Cross-Site Scripting.
- Weak Password Policy.
- Weak Session Cookie Configuration.
- Missing Authentication Rate Limiting.
- Broken Object Level Authorization / IDOR.
- Sensitive File Disclosure.
- Unrestricted File Upload.
- Local File Inclusion.
- Path Traversal / Arbitrary File Read.

Validation should confirm that each scanner can run without blocking the full pipeline and that findings are returned using the shared `Finding` model.

## Report Validation

A completed scan should produce a stored JSON report and a downloadable PDF report.

Report validation should confirm:

- The scan status changes to `Completed`.
- `overall_threat_level` is populated on the scan record.
- `full_report_json` is stored on the scan record.
- The PDF endpoint returns a valid PDF file.
- Findings use consistent IDs, severity labels, affected paths, descriptions, recommendations, and proof-of-concept evidence.
- Attack-chain findings appear only when correlation rules match existing findings.

## WebSocket Validation

The frontend should receive live scan messages from the backend while the background scan thread is running.

Expected telemetry includes:

- Scanner initialization messages.
- Discovery phase messages.
- Crawling activity.
- Attack surface extraction count.
- Scanner completion or finding messages.
- Correlation phase messages.
- Report-building messages.
- Scan completion or failure messages.

The current implementation uses Django Channels with an in-memory channel layer. This is suitable for the local demo but does not validate multi-process WebSocket behavior.

## Known Test Constraints

- Some files under `backend/tests/` are legacy or manual validation scripts and do not fully match the current active engine APIs.
- The crawler is limited to same-domain navigation and does not perform complex multi-step browser workflows.
- Response analysis is heuristic-based and may still produce false positives or false negatives.
- Active scans are not durable if the backend process exits.
- Findings are stored in memory during active scanner execution and then represented in the final report JSON.

## Evaluation Checklist

Use this checklist when reviewing the project as a graduation submission:

- The local setup can be completed from a clean environment.
- All three applications start on their documented ports.
- The frontend can start a scan successfully.
- The backend streams WebSocket telemetry during the scan.
- The scanner pipeline completes without blocking the API response.
- The generated report is downloadable after completion.
- Current implementation details are not confused with future roadmap features.
- Documentation links are accurate and consistent.
- The architecture is understandable from the README, architecture document, API reference, testing guide, and diagrams.
